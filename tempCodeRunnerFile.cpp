#include <iostream>
using namespace std;

#define V 5
#define INF 9999

void dijkstra(int graph[V][V], int src) {
    int dist[V], vis[V] = {0};

    // Initialize distances to infinity
    for (int i = 0; i < V; i++) dist[i] = INF;
    dist[src] = 0;

    for (int count = 0; count < V - 1; count++) {
        // Find the unvisited node with the minimum distance
        int min_d = INF, u = -1;
        for (int i = 0; i < V; i++) {
            if (!vis[i] && dist[i] < min_d) {
                min_d = dist[i]; 
                u = i;
            }
        }

        vis[u] = 1; // Mark the selected node as visited

        // Update distances of adjacent nodes
        for (int v = 0; v < V; v++) {
            if (!vis[v] && graph[u][v] && dist[u] + graph[u][v] < dist[v]) {
                dist[v] = dist[u] + graph[u][v];
            }
        }
    }

    // Print result
    cout << "Node \t Distance from Source " << src << "\n";
    for (int i = 0; i < V; i++) 
        cout << i << " \t\t " << dist[i] << "\n";
}

int main() {
    int network[V][V] = { 
        {0, 10, 0, 0, 5},
        {0, 0, 1, 0, 2},
        {0, 0, 0, 4, 0},
        {7, 0, 6, 0, 0},
        {0, 3, 9, 2, 0} 
    };
    
    dijkstra(network, 0);
    return 0;
}