Nome da interface
```ip link show```

Execução do broker control path
```sudo ./xdp_manual <INTERFACE>```

Para acompanhar os logs do subscriber em tempo real
```docker compose logs -f subscriber```

Visualizar o map
```sudo bpftool map dump name pkt_count_map```