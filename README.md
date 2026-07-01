# Broker Pub/Sub com eBPF/XDP

Broker publish/subscribe para mensagens UDP. O projeto usa eBPF/XDP para encaminhar publicações diretamente no datapath, evitando que elas sejam processadas pelo broker no user space.

## Referência

Este projeto foi baseado no artigo:

> Beihao Zhou, Samer Al-Kiswany e Mina Tahmasbi Arashloo. 2025.  
> **Toward eBPF-Accelerated Pub-Sub Systems.**  
> 3rd Workshop on eBPF and Kernel Extensions (eBPF '25), pp. 38–44.  
> [https://doi.org/10.1145/3748355.3748365](https://doi.org/10.1145/3748355.3748365)

O artigo propõe separar o control path, executado no user space, do data path de
encaminhamento de mensagens, acelerado no kernel com eBPF.

## Arquitetura

O projeto possui quatro componentes:

- **Publisher**: API HTTP em .NET que cria tópicos e envia publicações UDP.
- **Subscriber**: aplicação .NET que registra uma assinatura e recebe mensagens
  UDP na porta `11000`.
- **Control Path**: processo C no user space. Carrega e anexa o programa
  XDP, mantém os mapas e recebe comandos de controle na porta UDP `10000`.
- **Data Path**: programa eBPF/XDP que consulta o mapa pelo tópico e redireciona
  a publicação para o subscriber.

```text
                         comandos 0 e 1
Publisher/Subscriber ─────────────────────> Control Path :10000
                                                  │
                                                  │ atualiza
                                                  ▼
                                             broker_map
                                                  ▲
                                                  │ consulta
Publisher ── publicação UDP, comando 2 ──> XDP/Data Path
                                                  │
                                                  └────> Subscriber :11000
```

O `broker_map` associa uma chave de tópico a um destino:

```text
chave -> endereço IPv4, porta UDP e endereço MAC
```

Cada chave possui um byte e aponta para um único subscriber.

## Protocolo UDP

O payload começa com um byte de comando e um byte de chave:

| Comando | Formato | Função |
|---|---|---|
| `0` | `0<chave>` | Cria uma entrada vazia no mapa |
| `1` | `1<chave>` | Registra o IP e a porta de origem do subscriber |
| `2` | `2<chave><mensagem>` | Publica uma mensagem |

Os comandos `0` e `1` chegam ao Control Path. O comando `2` é interceptado pelo
XDP antes de chegar ao socket do broker.

Para destinos locais, o XDP altera a porta UDP e retorna `XDP_PASS`, permitindo
que a pilha local entregue o pacote. Para destinos remotos na mesma rede, altera
IP, porta e endereços Ethernet e retorna `XDP_TX`.

## Fluxo

1. O publisher cria uma chave com `/create-map`.
2. `/helper/subscribe` envia uma mensagem ao subscriber.
3. O subscriber responde ao broker usando seu socket da porta `11000`.
4. O Control Path grava o endereço do subscriber no `broker_map`.
5. O publisher envia uma publicação com `/publish`.
6. O XDP consulta o mapa e encaminha o pacote ao subscriber.

O endpoint `helper/subscribe` existe apenas para acionar o registro da assinatura
nesta prova de conceito.

## Requisitos

- Linux com suporte a eBPF e XDP
- `clang`, `gcc`, `make`, `libbpf` e headers do kernel
- privilégios de root para carregar e anexar o programa XDP
- Docker com Compose para executar Publisher e Subscriber
- .NET 10 caso as aplicações sejam executadas sem Docker

## Compilação

Compile primeiro o Data Path e depois o Control Path:

```bash
make -C Broker/DataPath
make -C Broker/ControlPath
```

## Execução no mesmo host

Tráfego destinado ao próprio host passa pela interface de loopback. Portanto, o
XDP deve ser anexado em `lo`:

```bash
cd Broker/ControlPath
sudo ./xdp_manual lo
```

Em outro terminal, inicie Publisher e Subscriber:

```bash
docker compose up --build
```

O Publisher fica disponível em `http://localhost:5000`.

Crie a chave `a`, registre o subscriber e publique:

```bash
curl -X POST http://localhost:5000/create-map \
  -H 'Content-Type: application/json' \
  -d '{"key":"a","text":""}'

curl -X POST http://localhost:5000/helper/subscribe \
  -H 'Content-Type: application/json' \
  -d '"a"'

curl -X POST http://localhost:5000/publish \
  -H 'Content-Type: application/json' \
  -d '{"key":"a","text":"hello"}'
```

## Execução entre máquinas

Execute o broker informando a interface conectada à rede:

```bash
sudo ./xdp_manual <interface>
```

Configure `BROKER_HOST` no Publisher e no Subscriber com o IPv4 do broker. O
subscriber deve estar alcançável na mesma rede de camada 2, pois o Control Path
resolve seu endereço MAC via ARP e o Data Path transmite com `XDP_TX`.

## Observabilidade

Logs das aplicações:

```bash
docker compose logs -f publisher subscriber
```

Conteúdo do mapa:

```bash
sudo bpftool map dump name broker_map
```

Logs emitidos pelo programa eBPF:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```
