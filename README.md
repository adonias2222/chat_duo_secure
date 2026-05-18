# Chat Duo Secure

App Flutter para **chat privado entre duas pessoas**, usando **Supabase**, criptografia ponta a ponta para mensagens/mídias e base de chamadas de áudio/vídeo com **WebRTC**.

## Recursos incluídos

- Login e cadastro com Supabase Auth.
- Bloqueio por `is_allowed` para permitir só duas pessoas.
- Interface moderna com gradiente, cards translúcidos, botões interativos e bolhas de mensagem.
- Chat 1–1 em tempo real com Supabase Realtime.
- Criptografia local com X25519 + AES-GCM.
- Texto criptografado antes de ir para o banco.
- Foto, vídeo e áudio criptografados antes de ir para o Supabase Storage.
- Gravação de áudio no app.
- Tela de chamada de áudio/vídeo com `flutter_webrtc`.
- GitHub Actions para compilar APK direto no GitHub.

> Esta é uma base/MVP para evoluir. Para produção real, implemente verificação de identidade, rotação de chaves, Double Ratchet, fluxo completo de aceitar chamada recebida e servidor TURN próprio.

## 1. Supabase

No Supabase, crie um projeto e copie:

```txt
Project URL
anon public key
```

Depois rode o SQL:

```txt
supabase/schema.sql
```

Crie também um bucket privado no Storage:

```txt
chat-media
```

## 2. Rodar localmente

Este starter não inclui as pastas geradas `android/ios`. Para gerar Android:

```bash
flutter create . --platforms=android --project-name chat_duo_secure --org br.com.chatduo
bash scripts/prepare_android.sh
flutter pub get
```

Rodar:

```bash
flutter run \
  --dart-define=SUPABASE_URL="SUA_URL" \
  --dart-define=SUPABASE_ANON_KEY="SUA_ANON_KEY"
```

## 3. Subir para o GitHub pelo Termux

```bash
pkg update -y
pkg install git gh unzip -y
unzip chat_duo_secure_starter.zip
cd chat_duo_secure
bash scripts/upload_github_termux.sh
```

O script usa:

```txt
GitHub: adonias2222
Repositório: chat_duo_secure
```

## 4. Compilar direto no GitHub

No repositório, configure os secrets:

```txt
Settings > Secrets and variables > Actions > New repository secret
```

Crie:

```txt
SUPABASE_URL
SUPABASE_ANON_KEY
```

Depois vá em:

```txt
Actions > Flutter Android APK > Run workflow
```

O APK debug ficará em **Artifacts**.

## 5. Liberar só duas pessoas

Depois que os dois usuários criarem conta, rode no SQL Editor:

```sql
update profiles
set is_allowed = true
where id in (
  'ID_USUARIO_1',
  'ID_USUARIO_2'
);
```

## 6. Próximas melhorias

- Tela de chamada recebida.
- Fluxo completo de answer/ICE candidates para conectar os dois lados.
- Notificação push.
- Reações com emoji.
- QR Code para verificar chave pública.
- Build release assinado no GitHub Actions.
