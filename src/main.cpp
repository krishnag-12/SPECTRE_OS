// =============================================================================
// S.P.E.C.T.R.E. - Secure Portable Encrypted Communication Terminal
//                  for Remote Environments
// =============================================================================

#define SIMULATOR_MODE 0   
#define ENABLE_RADIO_TASK 1  

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h> 
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

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET   -1

#define BTN_UP_PIN    32
#define BTN_DOWN_PIN  33
#define BTN_SEL_PIN   25

// =============================================================================
// ECDH KEY EXCHANGE & AES CONFIG
// =============================================================================

static uint8_t AES_KEY[32] = {0}; 
static bool keyExchangeComplete = false;

mbedtls_ecdh_context ecdh_ctx;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;

static uint8_t myPublicKey[65]; 
size_t pubKeyLen;

#define MAX_PAYLOAD_LEN   128
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
    uint8_t  magicByte;                         
    uint8_t  messageID;
    uint8_t  hopCount;
    uint8_t  payloadLen;                        
    uint8_t  iv[12];                            
    uint8_t  tag[16];                           
    uint8_t  encrypted[MAX_PAYLOAD_LEN];        
};

struct __attribute__((packed)) LoRaKeyExchangePacket {
    uint8_t  magicByte;                         
    uint8_t  pubKeyLen;
    uint8_t  publicKey[65];
};

// =============================================================================
// GLOBALS & DISPLAY SETUP
// =============================================================================

QueueHandle_t txQueue;
QueueHandle_t rxQueue;
TaskHandle_t  taskRadioHandle;

#if !SIMULATOR_MODE
  SX1278 radio = new Module(LORA_NSS_PIN, LORA_DIO0_PIN, LORA_RESET_PIN, LORA_DIO1_PIN);
#endif

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

AceButton btnUp(BTN_UP_PIN);
AceButton btnDown(BTN_DOWN_PIN);
AceButton btnSel(BTN_SEL_PIN);

volatile bool rxFlag = false;

enum MenuState { MENU_MAIN, MENU_INBOX, MENU_COMPOSE };
static MenuState   currentMenu = MENU_MAIN;
static int         menuCursor  = 0;
static bool        needRedraw  = false;
static MenuState   nextMenu    = MENU_MAIN;
static bool        menuChanged = false;

static const char* menuItems[] = {
    "MAYDAY TX", "EXTRACT TX", "REGROUP TX", "SITREP TX", "KEY EXCH TX", "INBOX"
};
static const int menuCount = 6;
static const char* tacMessages[] = {
    "MAYDAY! Sector 4. Immediate assistance required.",
    "Extraction requested at primary LZ. Awaiting confirmation.",
    "All units regroup at Checkpoint Bravo.",
    "Status nominal. Holding position. No enemy contact.",
    "BROADCASTING PUBLIC ECDH KEY..."
};

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
    mbedtls_ecdh_setup(&ecdh_ctx, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdh_make_public(&ecdh_ctx, &pubKeyLen, myPublicKey, sizeof(myPublicKey), mbedtls_ctr_drbg_random, &ctr_drbg);
    Serial.println("[Crypto] Keys generated successfully.");
}

bool deriveSharedAESKey(const uint8_t* peerPublicKey, size_t peerKeyLen) {
    Serial.println("[Crypto] Deriving shared secret from peer key...");
    mbedtls_ecdh_read_public(&ecdh_ctx, peerPublicKey, peerKeyLen);
    uint8_t sharedSecret[32];
    size_t secretLen = 0;
    mbedtls_ecdh_calc_secret(&ecdh_ctx, &secretLen, sharedSecret, sizeof(sharedSecret), mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_sha256(sharedSecret, secretLen, AES_KEY, 0);
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
// CORE 0: RADIO TASK
// =============================================================================
#if !SIMULATOR_MODE
void IRAM_ATTR onDio0Rise() { rxFlag = true; }
#endif

void taskRadioAndCrypto(void* pvParameters) {
    Serial.printf("[Radio] Task started on Core %d\n", xPortGetCoreID());
    
    int state = RADIOLIB_ERR_NONE; 
    LoRaPacket pkt;
    MessageEvent outMsg, inMsg;

#if !SIMULATOR_MODE
    state = radio.begin(LORA_FREQUENCY, LORA_BANDWIDTH, LORA_SF, LORA_CR, LORA_SYNC_WORD, LORA_TX_POWER);
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
            if (outMsg.messageID == 0xFE) {
                LoRaKeyExchangePacket keyPkt;
                keyPkt.magicByte = 0xAC;
                keyPkt.pubKeyLen = pubKeyLen;
                memcpy(keyPkt.publicKey, myPublicKey, pubKeyLen);
                
                radio.standby();
                state = radio.transmit((uint8_t*)&keyPkt, sizeof(LoRaKeyExchangePacket));
                rxFlag = false;
                radio.startReceive();
                continue;
            }

            if (!keyExchangeComplete) {
                MessageEvent errMsg;
                errMsg.messageID = 0xFF;
                strncpy(errMsg.payload, "ERR: Run Key Exchange.", MAX_PAYLOAD_LEN);
                xQueueSend(rxQueue, &errMsg, 0);
                continue;
            }

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
            size_t rxLen = radio.getPacketLength(); 
            uint8_t buf[sizeof(LoRaPacket)] = {0}; 
            
            if (radio.readData(buf, rxLen) == RADIOLIB_ERR_NONE) {
                if (buf[0] == 0xAC) {
                    LoRaKeyExchangePacket* rxKeyPkt = (LoRaKeyExchangePacket*)buf;
                    deriveSharedAESKey(rxKeyPkt->publicKey, rxKeyPkt->pubKeyLen);
                    memset(&inMsg, 0, sizeof(inMsg));
                    inMsg.messageID = 0xFD; 
                    strncpy(inMsg.payload, "SYS: Secure Key Exchanged!", MAX_PAYLOAD_LEN);
                    xQueueSend(rxQueue, &inMsg, 0);
                } 
                else if (buf[0] == 0xAB) {
                    if (!keyExchangeComplete) continue; 
                    LoRaPacket* rxPkt = (LoRaPacket*)buf;
                    memset(&inMsg, 0, sizeof(inMsg));
                    inMsg.messageID = rxPkt->messageID;
                    inMsg.hopCount  = rxPkt->hopCount;
                    
                    bool authOk = aes256Decrypt(rxPkt->encrypted, rxPkt->payloadLen, rxPkt->iv, rxPkt->tag, inMsg.payload);
                    if (authOk) {
                        xQueueSend(rxQueue, &inMsg, 0);
                        if (rxPkt->hopCount > 0) {
                            rxPkt->hopCount--;
                            radio.standby();
                            vTaskDelay((esp_random() % 200 + 50) / portTICK_PERIOD_MS);
                            size_t relaySize = sizeof(LoRaPacket) - MAX_PAYLOAD_LEN + rxPkt->payloadLen;
                            radio.transmit(buf, relaySize);
                            rxFlag = false;
                            radio.startReceive();
                        }
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
    display.fillRect(0, 0, 128, 9, SSD1306_WHITE);
    display.setTextSize(1);
    display.setTextColor(SSD1306_BLACK); 
    display.setCursor(1, 1);
    display.printf("B:%d%% S:%d %s", battery, signal, mode);
}

static void drawMainMenu() {
    display.clearDisplay();
    drawStatusBar(85, 72, "STBY");
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    int startY = 12;
    for (int i = 0; i < menuCount; i++) {
        display.setCursor(0, startY + (i * 8));
        if (i == menuCursor) {
            display.fillRect(0, startY + (i * 8) - 1, 128, 9, SSD1306_WHITE);
            display.setTextColor(SSD1306_BLACK);
            display.print("> "); display.print(menuItems[i]);
            display.setTextColor(SSD1306_WHITE); 
        } else {
            display.print("  "); display.print(menuItems[i]);
        }
    }
    display.display();
}

static void drawInbox(const MessageEvent& msg) {
    display.clearDisplay();
    drawStatusBar(85, 72, "RX");
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);
    display.setCursor(0, 12);
    display.printf("MsgID:%u Hops:%u", msg.messageID, msg.hopCount);
    display.drawLine(0, 21, 128, 21, SSD1306_WHITE);
    display.setCursor(0, 24);
    display.setTextWrap(true);
    display.print(msg.payload);
    display.display(); 
}

// =============================================================================
// BUTTON HANDLER
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
            if (menuCursor == menuCount - 1) { 
                nextMenu = MENU_INBOX; menuChanged = true;
            } else {
                MessageEvent txMsg;
                if (menuCursor == menuCount - 2) txMsg.messageID = 0xFE; 
                else txMsg.messageID = (uint8_t)(menuCursor + 1);
                
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

// =============================================================================
// NATIVE CORE 1: SETUP & MAIN UI LOOP
// =============================================================================

static uint32_t composeDoneMs = 0;
static bool     composePending = false;

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n==============================");
    Serial.println("  S.P.E.C.T.R.E. OS BOOTING");
    Serial.println("==============================");

    Serial.println("[Setup] Initializing display...");
    Wire.begin(21, 22);
    Wire.setClock(100000); 
    delay(50); // Let caps stabilize

    // true  = perform software reset sequence (critical for clone SSD1306 modules)
    // false = don't call Wire.begin() internally (we already locked the pins)
    if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C, true, false)) {
        Serial.println(F("\n\n[FATAL] SSD1306 allocation failed. Check wiring!\n\n"));
        while (true) { delay(100); } 
    }
    
    display.dim(false); // Make sure contrast isn't 0

    // =========================================================================
    // THE PROOF OF LIFE SCREEN
    // =========================================================================
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(2);
    display.setCursor(18, 15);
    display.println("SPECTRE");
    display.setTextSize(1);
    display.setCursor(16, 40);
    display.println("DISPLAY ONLINE");
    display.display();

    Serial.println("[Setup] Display OK.");
    delay(2500); // Wait 2.5 seconds to admire your fully working display
    // =========================================================================

    currentMenu = MENU_MAIN;
    drawMainMenu();

    initCryptoAndGenerateKeys();

    txQueue = xQueueCreate(QUEUE_DEPTH, sizeof(MessageEvent));
    rxQueue = xQueueCreate(QUEUE_DEPTH, sizeof(MessageEvent));
    
#if ENABLE_RADIO_TASK
    Serial.println("[Setup] Starting Background Radio Task on Core 0...");
    // 49152 byte stack allocation safely buffers mbedTLS memory demands
    xTaskCreatePinnedToCore(taskRadioAndCrypto, "RadioTask", 49152, NULL, 3, &taskRadioHandle, 0);
#endif

    pinMode(BTN_UP_PIN,   INPUT_PULLUP);
    pinMode(BTN_DOWN_PIN, INPUT_PULLUP);
    pinMode(BTN_SEL_PIN,  INPUT_PULLUP);
    ButtonConfig* config = ButtonConfig::getSystemButtonConfig();
    config->setEventHandler(handleButtonEvent);
    config->setFeature(ButtonConfig::kFeatureClick);
}

void loop() {
    // Non-blocking UI timer for composition screens
    if (composePending && (millis() - composeDoneMs > 1200)) {
        composePending = false;
        currentMenu = MENU_MAIN;
        drawMainMenu();
    }

    btnUp.check();
    btnDown.check();
    btnSel.check();

    if (menuChanged) {
        menuChanged = false;
        currentMenu = nextMenu;
        switch (currentMenu) {
            case MENU_MAIN:
                drawMainMenu();
                break;
            case MENU_INBOX:
                display.clearDisplay();
                drawStatusBar(85, 72, "RX");
                display.setTextColor(SSD1306_WHITE);
                display.setTextSize(1);
                display.setCursor(0, 15);
                display.println("== INBOX ==");
                display.drawLine(0, 25, 128, 25, SSD1306_WHITE);
                display.setCursor(0, 35);
                display.println("Awaiting tx...");
                display.display();
                break;
            case MENU_COMPOSE:
                display.clearDisplay();
                drawStatusBar(85, 72, "TX");
                display.setTextColor(SSD1306_WHITE);
                display.setTextSize(1);
                display.setCursor(0, 15);
                display.println("[ TRANSMITTING ]");
                display.setCursor(0, 30);
                display.setTextWrap(true);
                display.print(tacMessages[menuCursor]);
                display.display();
                
                composePending = true;
                composeDoneMs = millis();
                break;
        }
    }
    
    if (needRedraw) {
        needRedraw = false;
        if (currentMenu == MENU_MAIN) drawMainMenu();
    }

    // Process incoming radio messages
    MessageEvent inMsg;
    if (xQueueReceive(rxQueue, &inMsg, 0) == pdPASS) {
        if (inMsg.messageID == 0xFF) {
            display.clearDisplay();
            display.setTextColor(SSD1306_BLACK, SSD1306_WHITE); 
            display.setTextSize(1);
            display.setCursor(0, 15);
            display.println(" RADIO ERROR! ");
            display.setTextColor(SSD1306_WHITE);
            display.setCursor(0, 30);
            display.print(inMsg.payload);
            display.display();
        } else {
            drawInbox(inMsg);
            currentMenu = MENU_INBOX;
        }
    }
    
    // Yield to the RTOS scheduler to allow background tasks to run without blocking
    taskYIELD(); 
}