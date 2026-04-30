// =============================================================================
// S.P.E.C.T.R.E. - Secure Portable Encrypted Communication Terminal
//                  for Remote Environments
// =============================================================================

#define SIMULATOR_MODE 0   // 0 = real hardware

#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ILI9341.h>
#include <AceButton.h>

// Cryptography Libraries
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"

#if !SIMULATOR_MODE
  #include <RadioLib.h>
#endif

using namespace ace_button;

// =============================================================================
// PIN DEFINITIONS
// =============================================================================

#define LORA_FREQUENCY   433.0
#define LORA_BANDWIDTH   125.0
#define LORA_SF          10
#define LORA_CR          6
#define LORA_SYNC_WORD   0x34
#define LORA_TX_POWER    17
#define LORA_NSS_PIN     5
#define LORA_DIO0_PIN    26
#define LORA_RESET_PIN   14
#if SIMULATOR_MODE
  #define LORA_DIO1_PIN  -1
#else
  #define LORA_DIO1_PIN  RADIOLIB_NC
#endif

#define TFT_CS   15
#define TFT_DC    2
#define TFT_RST   4   

#define BTN_UP_PIN    32
#define BTN_DOWN_PIN  33
#define BTN_SEL_PIN   25

// =============================================================================
// ECDH KEY EXCHANGE & AES CONFIG
// =============================================================================

static uint8_t AES_KEY[32] = {0}; // Will be dynamically generated
static bool keyExchangeComplete = false;

mbedtls_ecdh_context ecdh_ctx;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

static uint8_t myPublicKey[65]; 
size_t pubKeyLen;

#define MAX_PAYLOAD_LEN   128
#define AES_BLOCK         16
#define QUEUE_DEPTH       5

// =============================================================================
// DATA STRUCTURES
// =============================================================================

struct MessageEvent {
    uint8_t messageID;
    uint8_t hopCount;
    char    payload[MAX_PAYLOAD_LEN];
};

struct __attribute__((packed)) LoRaPacket {
    uint8_t  magicByte;                         // 0xAB = valid Encrypted S.P.E.C.T.R.E. packet
    uint8_t  messageID;
    uint8_t  hopCount;
    uint8_t  payloadLen;                        
    uint8_t  iv[12];                            
    uint8_t  tag[16];                           
    uint8_t  encrypted[MAX_PAYLOAD_LEN];        
};

struct __attribute__((packed)) LoRaKeyExchangePacket {
    uint8_t  magicByte;                         // 0xAC = Key Exchange Packet
    uint8_t  pubKeyLen;
    uint8_t  publicKey[65];
};

// =============================================================================
// GLOBALS
// =============================================================================

QueueHandle_t txQueue;
QueueHandle_t rxQueue;
TaskHandle_t  taskRadioHandle, taskUIHandle, taskInputHandle;

#if !SIMULATOR_MODE
  SX1278 radio = new Module(LORA_NSS_PIN, LORA_DIO0_PIN, LORA_RESET_PIN, LORA_DIO1_PIN);
#endif

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

AceButton btnUp(BTN_UP_PIN);
AceButton btnDown(BTN_DOWN_PIN);
AceButton btnSel(BTN_SEL_PIN);

volatile bool rxFlag = false;

// =============================================================================
// MENU STATE
// =============================================================================

enum MenuState { MENU_MAIN, MENU_INBOX, MENU_COMPOSE };

static MenuState   currentMenu = MENU_MAIN;
static int         menuCursor  = 0;

static const char* menuItems[] = {
    "MAYDAY TX", "EXTRACT TX", "REGROUP TX", "SITREP TX", "KEY EXCH TX", "INBOX"
};
static const int menuCount = 6;

static const char* tacMessages[] = {
    "MAYDAY! Sector 4. Immediate assistance required.",
    "Extraction requested at primary LZ. Awaiting confirmation.",
    "All units regroup at Checkpoint Bravo.",
    "Status nominal. Holding position. No enemy contact.",
    "BROADCASTING PUBLIC ECDH KEY..." // Matches the "KEY EXCH TX" index
};

static volatile bool      needRedraw  = false;
static volatile MenuState nextMenu    = MENU_MAIN;
static volatile bool      menuChanged = false;

// =============================================================================
// CRYPTO HELPERS
// =============================================================================

void initCryptoAndGenerateKeys() {
    Serial.println("[Crypto] Initializing RNG and ECDH...");
    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    const char *pers = "spectre_rng";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    mbedtls_ecp_group_load(&ecdh_ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdh_gen_public(&ecdh_ctx.MBEDTLS_PRIVATE(grp), &ecdh_ctx.MBEDTLS_PRIVATE(d), &ecdh_ctx.MBEDTLS_PRIVATE(Q), mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ecp_point_write_binary(&ecdh_ctx.MBEDTLS_PRIVATE(grp), &ecdh_ctx.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &pubKeyLen, myPublicKey, sizeof(myPublicKey));
    
    Serial.println("[Crypto] Keys generated successfully.");
}

bool deriveSharedAESKey(const uint8_t* peerPublicKey, size_t peerKeyLen) {
    Serial.println("[Crypto] Deriving shared secret from peer key...");
    mbedtls_ecdh_read_public(&ecdh_ctx, peerPublicKey, peerKeyLen);
    mbedtls_ecdh_compute_shared(&ecdh_ctx.MBEDTLS_PRIVATE(grp), &ecdh_ctx.MBEDTLS_PRIVATE(z), &ecdh_ctx.MBEDTLS_PRIVATE(Qp), &ecdh_ctx.MBEDTLS_PRIVATE(d), mbedtls_ctr_drbg_random, &ctr_drbg);

    uint8_t sharedSecret[32];
    mbedtls_mpi_write_binary(&ecdh_ctx.MBEDTLS_PRIVATE(z), sharedSecret, sizeof(sharedSecret));
    mbedtls_sha256(sharedSecret, sizeof(sharedSecret), AES_KEY, 0);

    keyExchangeComplete = true;
    Serial.println("[Crypto] AES_KEY derived and locked. Comms are now secure.");
    return true;
}

static int aes256Encrypt(const char* plaintext, const uint8_t* iv, uint8_t* ciphertext, uint8_t* tag) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
    size_t textLen = strnlen(plaintext, MAX_PAYLOAD_LEN - 1);
    mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, textLen, iv, 12, NULL, 0, (const unsigned char*)plaintext, ciphertext, 16, tag);
    mbedtls_gcm_free(&ctx);
    return (int)textLen;
}

static bool aes256Decrypt(const uint8_t* ciphertext, int len, const uint8_t* iv, const uint8_t* tag, char* plaintext) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, AES_KEY, 256);
    int ret = mbedtls_gcm_auth_decrypt(&ctx, len, iv, 12, NULL, 0, tag, 16, ciphertext, (unsigned char*)plaintext);
    mbedtls_gcm_free(&ctx);
    if (ret == 0) {
        plaintext[len] = '\0';
        return true;
    }
    return false;
}

// =============================================================================
// ISR
// =============================================================================
#if !SIMULATOR_MODE
void IRAM_ATTR onDio0Rise() { rxFlag = true; }
#endif

// =============================================================================
// CORE 0: RADIO & CRYPTO TASK
// =============================================================================
void taskRadioAndCrypto(void* pvParameters) {
    Serial.printf("[Radio] Task started on Core %d\n", xPortGetCoreID());
    LoRaPacket pkt;
    MessageEvent outMsg, inMsg;

#if !SIMULATOR_MODE
    int state = radio.begin(LORA_FREQUENCY, LORA_BANDWIDTH, LORA_SF, LORA_CR, LORA_SYNC_WORD, LORA_TX_POWER);
    if (state != RADIOLIB_ERR_NONE) {
        MessageEvent errMsg;
        errMsg.messageID = 0xFF;
        snprintf(errMsg.payload, MAX_PAYLOAD_LEN, "LoRa INIT FAIL! Code: %d", state);
        xQueueSend(rxQueue, &errMsg, portMAX_DELAY);
        vTaskSuspend(NULL);
    }
    attachInterrupt(digitalPinToInterrupt(LORA_DIO0_PIN), onDio0Rise, RISING);
    radio.startReceive();
    Serial.println("[Radio] LoRa initialised OK.");
#endif

    for (;;) {
        if (xQueueReceive(txQueue, &outMsg, 0) == pdPASS) {
            
            // Handle Key Exchange Transmission
            if (outMsg.messageID == 0xFE) {
                LoRaKeyExchangePacket keyPkt;
                keyPkt.magicByte = 0xAC;
                keyPkt.pubKeyLen = pubKeyLen;
                memcpy(keyPkt.publicKey, myPublicKey, pubKeyLen);
                
                radio.standby();
                state = radio.transmit((uint8_t*)&keyPkt, sizeof(LoRaKeyExchangePacket));
                rxFlag = false;
                radio.startReceive();
                Serial.println("[Radio][TX] Key Exchange Broadcast Sent.");
                continue;
            }

            // Prevent transmitting if we don't have a shared key
            if (!keyExchangeComplete) {
                MessageEvent errMsg;
                errMsg.messageID = 0xFF;
                strncpy(errMsg.payload, "ERR: No Shared Key! Run Key Exchange.", MAX_PAYLOAD_LEN);
                xQueueSend(rxQueue, &errMsg, 0);
                continue;
            }

            // Normal Encrypted Transmission
            Serial.printf("[Radio][TX] MsgID %u: \"%s\"\n", outMsg.messageID, outMsg.payload);
            memset(&pkt, 0, sizeof(pkt));
            pkt.magicByte  = 0xAB;
            pkt.messageID  = outMsg.messageID;
            pkt.hopCount   = outMsg.hopCount;
            esp_fill_random(pkt.iv, 12);

            int cLen = aes256Encrypt(outMsg.payload, pkt.iv, pkt.encrypted, pkt.tag);
            pkt.payloadLen = (uint8_t)cLen;

#if !SIMULATOR_MODE
            radio.standby();
            size_t pktSize = sizeof(LoRaPacket) - MAX_PAYLOAD_LEN + cLen;
            state = radio.transmit((uint8_t*)&pkt, pktSize);
            rxFlag = false;
            radio.startReceive();
#endif
        }

#if !SIMULATOR_MODE
        if (rxFlag) {
            rxFlag = false;
            
            // --> CRITICAL FIX: Get actual packet length from the LoRa chip
            size_t rxLen = radio.getPacketLength(); 
            uint8_t buf[sizeof(LoRaPacket)] = {0}; // Zero-out buffer for safety
            
            if (radio.readData(buf, rxLen) == RADIOLIB_ERR_NONE) {
                
                // Handle Key Exchange Reception
                if (buf[0] == 0xAC) {
                    LoRaKeyExchangePacket* rxKeyPkt = (LoRaKeyExchangePacket*)buf;
                    deriveSharedAESKey(rxKeyPkt->publicKey, rxKeyPkt->pubKeyLen);
                    
                    memset(&inMsg, 0, sizeof(inMsg));
                    inMsg.messageID = 0xFD; // System Info ID
                    strncpy(inMsg.payload, "SYS: Secure Key Exchanged!", MAX_PAYLOAD_LEN);
                    xQueueSend(rxQueue, &inMsg, 0);
                } 
                // Handle Normal Encrypted Reception
                else if (buf[0] == 0xAB) {
                    if (!keyExchangeComplete) continue; // Ignore if we can't decrypt

                    LoRaPacket* rxPkt = (LoRaPacket*)buf;
                    memset(&inMsg, 0, sizeof(inMsg));
                    inMsg.messageID = rxPkt->messageID;
                    inMsg.hopCount  = rxPkt->hopCount;
                    
                    bool authOk = aes256Decrypt(rxPkt->encrypted, rxPkt->payloadLen, rxPkt->iv, rxPkt->tag, inMsg.payload);

                    if (authOk) {
                        Serial.printf("[Radio][RX] Decrypted: \"%s\"\n", inMsg.payload);
                        xQueueSend(rxQueue, &inMsg, 0);

                        // Mesh Relay Logic
                        if (rxPkt->hopCount > 0) {
                            rxPkt->hopCount--;
                            radio.standby();
                            vTaskDelay((esp_random() % 200 + 50) / portTICK_PERIOD_MS);
                            size_t relaySize = sizeof(LoRaPacket) - MAX_PAYLOAD_LEN + rxPkt->payloadLen;
                            radio.transmit(buf, relaySize);
                            rxFlag = false;
                            radio.startReceive();
                        }
                    } else {
                        Serial.println("[Radio][RX] Auth failed. Packet modified or wrong key!");
                    }
                }
            }
        }
#endif
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }
}

// =============================================================================
// DISPLAY HELPERS
// =============================================================================

void drawStatusBar(int battery, int signal, const char* mode) {
    tft.fillRect(0, 0, 320, 16, ILI9341_DARKGREY);
    tft.setTextSize(1);
    tft.setTextColor(ILI9341_WHITE);
    tft.setCursor(3, 4);   tft.print("BAT:"); tft.print(battery); tft.print("%");
    tft.setCursor(110, 4); tft.print("SIG:"); tft.print(signal);
    tft.setCursor(220, 4);
    tft.setTextColor(strcmp(mode, "TX") == 0 ? ILI9341_RED : ILI9341_GREEN);
    tft.print("Mode:"); tft.print(mode);
}

void drawBootLogo() {
    tft.fillScreen(ILI9341_BLACK);
    tft.setTextColor(ILI9341_GREEN);
    tft.setTextSize(1);
    int y = 30;
    tft.setCursor(5, y);     tft.println("   ___  ____  ____  ___  ____  ____  ____");
    tft.setCursor(5, y+=10); tft.println("  / __)(  _ \\( ___)/ __)(_  _)(  _ \\( ___)");
    tft.setCursor(5, y+=10); tft.println("  \\__ \\ ) _/ ) _) ( (__   )(   )   / ) _) ");
    tft.setCursor(5, y+=10); tft.println("  (___/(__)  (____) \\___) (__) (_)\\_)(____) ");
    tft.setTextSize(2);
    tft.setTextColor(ILI9341_WHITE);
    tft.setCursor(55, y+=20); tft.println("S.P.E.C.T.R.E OS");
    tft.drawFastHLine(0, y+=25, 320, ILI9341_GREEN);
    tft.setTextSize(1);
    tft.setTextColor(ILI9341_CYAN);
    tft.setCursor(85, y+=10); tft.println("Initializing systems...");
    tft.drawRect(40, y+=20, 240, 10, ILI9341_WHITE);
    for (int i = 0; i <= 240; i += 20) {
        tft.fillRect(41, y+1, i, 8, ILI9341_GREEN);
        delay(80);
    }
    tft.setTextColor(ILI9341_GREEN);
    tft.setCursor(120, y+18);
    tft.println("[ OK ]");
}

static void drawMainMenu() {
    tft.fillScreen(ILI9341_BLACK);
    drawStatusBar(85, 72, "STBY");
    tft.setTextSize(2);
    tft.setTextColor(ILI9341_GREEN);
    tft.setCursor(70, 30);
    tft.println("S.P.E.C.T.R.E OS");
    tft.drawFastHLine(0, 55, 320, ILI9341_GREEN);
    tft.setTextSize(1);
    for (int i = 0; i < menuCount; i++) {
        tft.setCursor(20, 75 + i * 20);
        if (i == menuCursor) {
            tft.setTextColor(ILI9341_BLACK, ILI9341_GREEN);
            tft.print("> ["); tft.print(i+1); tft.print("] "); tft.println(menuItems[i]);
        } else {
            tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
            tft.print("  ["); tft.print(i+1); tft.print("] "); tft.println(menuItems[i]);
        }
    }
    tft.drawFastHLine(0, 200, 320, ILI9341_DARKGREY);
    tft.setTextColor(ILI9341_DARKGREY, ILI9341_BLACK);
    tft.setCursor(85, 210);
    tft.println("SPECTRE OS v0.3-beta"); 
}

static void drawInbox(const MessageEvent& msg) {
    tft.fillScreen(ILI9341_BLACK);
    drawStatusBar(85, 72, "RX");
    tft.setTextColor(ILI9341_CYAN, ILI9341_BLACK);
    tft.setTextSize(2);
    tft.setCursor(5, 25); tft.print("== INBOX ==");
    tft.drawFastHLine(0, 45, 320, ILI9341_CYAN);
    tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
    tft.setTextSize(1);
    tft.setTextWrap(true);
    tft.setCursor(5, 55); tft.print(msg.payload);
    tft.setTextColor(ILI9341_YELLOW, ILI9341_BLACK);
    char info[32];
    snprintf(info, sizeof(info), "MsgID:%u Hops:%u", msg.messageID, msg.hopCount);
    tft.setCursor(5, tft.height() - 14);
    tft.print(info);
}

// =============================================================================
// CORE 1: UI TASK
// =============================================================================
void taskUI(void* pvParameters) {
    Serial.printf("[UI] Task started on Core %d\n", xPortGetCoreID());
    currentMenu = MENU_MAIN;
    drawMainMenu();

    MessageEvent inMsg;
    for (;;) {
        if (menuChanged) {
            menuChanged = false;
            currentMenu = (MenuState)nextMenu;
            switch (currentMenu) {
                case MENU_MAIN:
                    drawMainMenu();
                    break;
                case MENU_INBOX:
                    tft.fillScreen(ILI9341_BLACK);
                    drawStatusBar(85, 72, "RX");
                    tft.setTextColor(ILI9341_CYAN, ILI9341_BLACK);
                    tft.setTextSize(2);
                    tft.setCursor(5, 25); tft.print("== INBOX ==");
                    tft.drawFastHLine(0, 45, 320, ILI9341_CYAN);
                    tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
                    tft.setTextSize(1);
                    tft.setCursor(5, 55); tft.print("Awaiting secure transmission...");
                    break;
                case MENU_COMPOSE:
                    tft.fillScreen(ILI9341_BLACK);
                    drawStatusBar(85, 72, "TX");
                    tft.setTextColor(ILI9341_YELLOW, ILI9341_BLACK);
                    tft.setTextSize(2);
                    tft.setCursor(5, 25); tft.print("[ TRANSMITTING ]");
                    tft.setTextSize(1);
                    tft.setTextColor(ILI9341_WHITE, ILI9341_BLACK);
                    tft.setCursor(5, 55); tft.print(tacMessages[menuCursor]);
                    vTaskDelay(1200 / portTICK_PERIOD_MS);
                    currentMenu = MENU_MAIN;
                    drawMainMenu();
                    break;
            }
        }
        if (needRedraw) {
            needRedraw = false;
            if (currentMenu == MENU_MAIN) drawMainMenu();
        }
        if (xQueueReceive(rxQueue, &inMsg, 0) == pdPASS) {
            if (inMsg.messageID == 0xFF) {
                tft.fillScreen(ILI9341_RED);
                tft.setTextColor(ILI9341_WHITE, ILI9341_RED);
                tft.setTextSize(1);
                tft.setCursor(5, 20); tft.print("RADIO ERROR!");
                tft.setCursor(5, 40); tft.print(inMsg.payload);
            } else {
                drawInbox(inMsg);
                currentMenu = MENU_INBOX;
            }
        }
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }
}

// =============================================================================
// BUTTON HANDLER & INPUT TASK
// =============================================================================
static void handleButtonEvent(AceButton* button, uint8_t eventType, uint8_t) {
    if (eventType != AceButton::kEventPressed) return;
    uint8_t pin = button->getPin();
    if (currentMenu == MENU_MAIN) {
        if (pin == BTN_UP_PIN) {
            menuCursor = (menuCursor - 1 + menuCount) % menuCount;
            needRedraw = true;
        } else if (pin == BTN_DOWN_PIN) {
            menuCursor = (menuCursor + 1) % menuCount;
            needRedraw = true;
        } else if (pin == BTN_SEL_PIN) {
            if (menuCursor == menuCount - 1) { // INBOX selected
                nextMenu = MENU_INBOX; menuChanged = true;
            } else {
                MessageEvent txMsg;
                // If "KEY EXCH TX" is selected (index 4)
                if (menuCursor == menuCount - 2) {
                    txMsg.messageID = 0xFE; // Special trigger ID
                } else {
                    txMsg.messageID = (uint8_t)(menuCursor + 1);
                }
                
                txMsg.hopCount  = 3;
                strncpy(txMsg.payload, tacMessages[menuCursor], MAX_PAYLOAD_LEN - 1);
                txMsg.payload[MAX_PAYLOAD_LEN - 1] = '\0';
                
                xQueueSend(txQueue, &txMsg, 0);
                nextMenu = MENU_COMPOSE; menuChanged = true;
            }
        }
    } else {
        nextMenu = MENU_MAIN; menuChanged = true;
    }
}

void taskInput(void* pvParameters) {
    Serial.printf("[Input] Task started on Core %d\n", xPortGetCoreID());
    pinMode(BTN_UP_PIN,   INPUT_PULLUP);
    pinMode(BTN_DOWN_PIN, INPUT_PULLUP);
    pinMode(BTN_SEL_PIN,  INPUT_PULLUP);
    ButtonConfig* config = ButtonConfig::getSystemButtonConfig();
    config->setEventHandler(handleButtonEvent);
    config->setFeature(ButtonConfig::kFeatureClick);
    config->setFeature(ButtonConfig::kFeatureLongPress);
    for (;;) {
        btnUp.check();
        btnDown.check();
        btnSel.check();
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}

// =============================================================================
// SETUP & LOOP
// =============================================================================
void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n==============================");
    Serial.println("  S.P.E.C.T.R.E. OS BOOTING");
    Serial.println("==============================");

    Serial.println("[Setup] Initializing display...");
    
    // Lock the SPI bus and free the CS pin for Adafruit
    SPI.begin(18, 19, 23, -1); 
    
    tft.begin();
    tft.setRotation(3);
    tft.fillScreen(ILI9341_BLACK);
    Serial.println("[Setup] Display OK.");

    // Generate our public/private keypair at boot
    initCryptoAndGenerateKeys();

    drawBootLogo();
    delay(1500);
    drawMainMenu();

    txQueue = xQueueCreate(QUEUE_DEPTH, sizeof(MessageEvent));
    rxQueue = xQueueCreate(QUEUE_DEPTH, sizeof(MessageEvent));
    if (!txQueue || !rxQueue) {
        Serial.println("[FATAL] Queue creation failed.");
        while (true) {}
    }

    Serial.println("[Setup] Starting RTOS tasks...");
    
    // Increased stack size from 8192 to 24576 to prevent mbedtls stack overflow
    xTaskCreatePinnedToCore(taskRadioAndCrypto, "RadioTask",  24576, NULL, 3, &taskRadioHandle, 0);
    xTaskCreatePinnedToCore(taskUI,             "UITask",     6144,  NULL, 2, &taskUIHandle,    1);
    xTaskCreatePinnedToCore(taskInput,          "InputTask",  4096,  NULL, 3, &taskInputHandle, 1);
}

void loop() {
    vTaskDelete(NULL);
}