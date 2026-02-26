# Detection-Engineering

Hello world!


```mermaid
%%{init: {'theme': 'base', 'themeVariables': { 'primaryColor': '#ffcc00', 'edgeColor': '#ffffff'}}}%%
graph LR
    A[Inbound Traffic] --> B{WAF Filter}
    B -- Block --> C[Deny Log]
    B -- Allow --> D[Backend]
    
    style A fill:#f96,stroke:#333,stroke-width:4px
    style C fill:#f00,color:#fff
    style D fill:#00ff00
