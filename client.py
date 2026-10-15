import asyncio
import json
import websockets
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

SERVER = "ws://localhost:8080/ws"

async def main():
    # Генерируем пару ключей — это и есть наш "аккаунт"
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = pub_bytes.hex()

    print(f"Твой анонимный ID: nexus:{pub_hex[:16]}...")

    async with websockets.connect(SERVER) as ws:
        # 1. Hello — запрос челленджа
        await ws.send(json.dumps({"type": "hello"}))
        resp = json.loads(await ws.recv())
        nonce = resp["nonce"]

        # 2. Подписываем nonce приватным ключом
        signature = private_key.sign(nonce.encode()).hex()

        await ws.send(json.dumps({
            "type": "auth",
            "pubkey": pub_hex,
            "signature": signature,
            "nonce": nonce,
        }))
        resp = json.loads(await ws.recv())
        print("Auth:", resp)

        if resp.get("type") != "auth_ok":
            print("Не удалось аутентифицироваться")
            return

        # 3. Отправляем сообщение
        await ws.send(json.dumps({
            "type": "message",
            "channel": "general",
            "content": "Привет, анонимы!",
        }))

        # Слушаем входящие
        while True:
            msg = await ws.recv()
            print("<<", msg)

asyncio.run(main())