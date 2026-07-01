Nome da interface
```ip link show```

Execução do broker control path
```sudo ./xdp_manual <INTERFACE>```

Para acompanhar os logs do subscriber em tempo real
```docker compose logs -f subscriber```

Visualizar o map
```sudo bpftool map dump name broker_map```

Para acompanhar os logs do data path em tempo real
```sudo cat /sys/kernel/debug/tracing/trace_pipe```