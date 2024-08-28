
# Captura e Análise de Pacotes HTTPS

Este projeto fornece um script Python para capturar e analisar pacotes de rede HTTPS. O script usa a biblioteca `Scapy` para captura de pacotes e a biblioteca `whois` para realizar consultas WHOIS e identificar domínios associados a endereços IP.

### Clone o repositório
```bash
git clone https://github.com/JoaoVictorFBarros/Sniffer.git
```

### Instalação das Dependências

Se ainda não tiver as bibliotecas instaladas, use:

```
pip install scapy python-whois
```

### Executando o Projeto

Para iniciar o programa, execute:

```
sudo python3 main.py
```
Quando solicitado, insira a interface de rede a ser usada para captura, como `eth0` para conexões Ethernet ou `wlan0` para conexões Wi-Fi.

### Observações
- Você pode verificar o nome da interface de rede com:
    ```
    ifconfig
    ```
- Pode ser necessário rodar a aplicação como superusuário para ter o acesso necessário. Em caso de erro na importação tente instalar as dependencias com o mesmo usuário que executa aplicação.

<div align="center">
<img src=print.png >

<i><b>Simulação</b> da execução do programa</i>
</div>

## Funcionamento das Requisições HTTPS

Quando um cliente (como um navegador) faz uma requisição HTTPS, ele está enviando dados criptografados para um servidor web. O HTTPS (Hypertext Transfer Protocol Secure) é uma versão segura do HTTP e utiliza criptografia TLS/SSL para garantir a privacidade e a integridade dos dados transmitidos.

### Processo de Requisição HTTPS:
1. **Estabelecimento da Conexão**: O cliente e o servidor estabelecem uma conexão segura através do protocolo TLS/SSL.
2. **Handshake TLS/SSL**: Durante o handshake, o cliente e o servidor trocam certificados digitais para autenticar a identidade e negociar chaves criptográficas.
3. **Troca de Dados**: Uma vez estabelecida a conexão segura, o cliente pode enviar requisições HTTP que são criptografadas antes de serem enviadas pela rede. O servidor responde com dados criptografados.
4. **Encerramento da Conexão**: Após a troca de dados, a conexão segura é encerrada.

Do ponto de vista das redes de computadores, o HTTPS usa a porta 443 para a comunicação, e os pacotes são encapsulados em pacotes IP e TCP.
