import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:image_picker/image_picker.dart';
import 'package:just_audio/just_audio.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:record/record.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

class Env {
  static const supabaseUrl = String.fromEnvironment('SUPABASE_URL');
  static const supabaseAnonKey = String.fromEnvironment('SUPABASE_ANON_KEY');
  static bool get ok => supabaseUrl.isNotEmpty && supabaseAnonKey.isNotEmpty;
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (Env.ok) {
    await Supabase.initialize(url: Env.supabaseUrl, anonKey: Env.supabaseAnonKey);
  }
  runApp(const ChatDuoApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) => const ChatDuoApp();
}

SupabaseClient get sb => Supabase.instance.client;
String get uid => sb.auth.currentUser!.id;

String firstLetter(String? text) {
  final value = (text ?? '').trim();
  if (value.isEmpty) return 'U';
  return value.characters.first.toUpperCase();
}

void toast(BuildContext context, String text) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
}

InputDecoration field(String label, IconData icon) {
  return InputDecoration(
    labelText: label,
    prefixIcon: Icon(icon),
    filled: true,
    fillColor: Colors.white.withOpacity(.08),
    border: OutlineInputBorder(borderRadius: BorderRadius.circular(22), borderSide: BorderSide.none),
  );
}

class ChatDuoApp extends StatelessWidget {
  const ChatDuoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Chat Duo Secure',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        scaffoldBackgroundColor: const Color(0xFF070A16),
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF6C63FF), brightness: Brightness.dark),
      ),
      home: const AuthGate(),
    );
  }
}

class AuthGate extends StatelessWidget {
  const AuthGate({super.key});

  @override
  Widget build(BuildContext context) {
    if (!Env.ok) return const SetupPage();
    return StreamBuilder<AuthState>(
      stream: sb.auth.onAuthStateChange,
      builder: (context, snapshot) {
        return sb.auth.currentSession == null ? const LoginPage() : const HomePage();
      },
    );
  }
}

class SetupPage extends StatelessWidget {
  const SetupPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DuoBackground(
        child: Center(
          child: GlassCard(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.lock_rounded, size: 48),
                const SizedBox(height: 16),
                Text('Configure o Supabase', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
                const SizedBox(height: 8),
                const Text('Adicione SUPABASE_URL e SUPABASE_ANON_KEY nos Secrets do GitHub Actions.'),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class DuoBackground extends StatelessWidget {
  const DuoBackground({super.key, required this.child});
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF07111F), Color(0xFF181139), Color(0xFF063847), Color(0xFF070A16)],
        ),
      ),
      child: Stack(
        children: [
          Positioned(top: -80, left: -80, child: _Glow(size: 220, color: Color(0xFF6C63FF))),
          Positioned(bottom: 40, right: -80, child: _Glow(size: 240, color: Color(0xFF00E5FF))),
          child,
        ],
      ),
    );
  }
}

class _Glow extends StatelessWidget {
  const _Glow({required this.size, required this.color});
  final double size;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        boxShadow: [BoxShadow(color: color.withOpacity(.22), blurRadius: 100, spreadRadius: 60)],
      ),
    );
  }
}

class GlassCard extends StatelessWidget {
  const GlassCard({super.key, required this.child, this.padding = const EdgeInsets.all(20)});
  final Widget child;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.all(18),
      padding: padding,
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(.08),
        borderRadius: BorderRadius.circular(28),
        border: Border.all(color: Colors.white.withOpacity(.12)),
        boxShadow: [BoxShadow(color: Colors.black.withOpacity(.25), blurRadius: 28, offset: const Offset(0, 18))],
      ),
      child: child,
    );
  }
}

class E2eeService {
  E2eeService._();
  static final instance = E2eeService._();
  final _storage = const FlutterSecureStorage();
  final _x25519 = X25519();
  final _aes = AesGcm.with256bits();

  Future<SimpleKeyPair> keyPair() async {
    final private = await _storage.read(key: 'duo_private_key');
    final public = await _storage.read(key: 'duo_public_key');
    if (private != null && public != null) {
      return SimpleKeyPairData(
        base64Decode(private),
        publicKey: SimplePublicKey(base64Decode(public), type: KeyPairType.x25519),
        type: KeyPairType.x25519,
      );
    }
    final pair = await _x25519.newKeyPair();
    final data = await pair.extract();
    final pub = await pair.extractPublicKey();
    await _storage.write(key: 'duo_private_key', value: base64Encode(data.bytes));
    await _storage.write(key: 'duo_public_key', value: base64Encode(pub.bytes));
    return pair;
  }

  Future<String> publicKeyBase64() async {
    final pub = await (await keyPair()).extractPublicKey();
    return base64Encode(pub.bytes);
  }

  Future<SecretKey> sharedKey(String otherPublicKey, String chatId) async {
    final raw = await _x25519.sharedSecretKey(
      keyPair: await keyPair(),
      remotePublicKey: SimplePublicKey(base64Decode(otherPublicKey), type: KeyPairType.x25519),
    );
    return Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: raw,
      nonce: utf8.encode(chatId),
      info: utf8.encode('chat-duo-secure-v1'),
    );
  }

  Future<Map<String, String>> encryptText(String text, SecretKey key) async {
    final box = await _aes.encrypt(utf8.encode(text), secretKey: key);
    return {
      'cipher_text': base64Encode(box.cipherText),
      'nonce': base64Encode(box.nonce),
      'mac': base64Encode(box.mac.bytes),
    };
  }

  Future<String> decryptText(Map<String, dynamic> msg, SecretKey key) async {
    final clear = await _aes.decrypt(
      SecretBox(
        base64Decode(msg['cipher_text']?.toString() ?? ''),
        nonce: base64Decode(msg['nonce']?.toString() ?? ''),
        mac: Mac(base64Decode(msg['mac']?.toString() ?? '')),
      ),
      secretKey: key,
    );
    return utf8.decode(clear);
  }

  Future<EncryptedBytes> encryptBytes(Uint8List bytes, SecretKey key) async {
    final box = await _aes.encrypt(bytes, secretKey: key);
    return EncryptedBytes(
      bytes: Uint8List.fromList(box.cipherText),
      nonce: base64Encode(box.nonce),
      mac: base64Encode(box.mac.bytes),
    );
  }

  Future<Uint8List> decryptBytes(Uint8List bytes, String nonce, String mac, SecretKey key) async {
    final clear = await _aes.decrypt(
      SecretBox(bytes, nonce: base64Decode(nonce), mac: Mac(base64Decode(mac))),
      secretKey: key,
    );
    return Uint8List.fromList(clear);
  }
}

class EncryptedBytes {
  const EncryptedBytes({required this.bytes, required this.nonce, required this.mac});
  final Uint8List bytes;
  final String nonce;
  final String mac;
}

class AuthService {
  Future<void> syncProfile({String fallbackName = 'Usuário'}) async {
    final user = sb.auth.currentUser;
    if (user == null) return;
    final publicKey = await E2eeService.instance.publicKeyBase64();
    await sb.from('profiles').upsert({
      'id': user.id,
      'name': (user.userMetadata?['name'] as String?) ?? fallbackName,
      'public_key': publicKey,
      'online': true,
      'last_seen': DateTime.now().toIso8601String(),
    });
  }

  Future<void> login(String email, String password) async {
    await sb.auth.signInWithPassword(email: email, password: password);
    await syncProfile(fallbackName: email.split('@').first);
  }

  Future<void> register(String name, String email, String password) async {
    await sb.auth.signUp(email: email, password: password, data: {'name': name});
    if (sb.auth.currentUser != null) await syncProfile(fallbackName: name);
  }

  Future<void> logout() async {
    final user = sb.auth.currentUser;
    if (user != null) {
      await sb.from('profiles').update({'online': false, 'last_seen': DateTime.now().toIso8601String()}).eq('id', user.id);
    }
    await sb.auth.signOut();
  }
}

class ChatService {
  final crypto = E2eeService.instance;

  Future<String?> ensureChat() async {
    final me = await sb.from('profiles').select('is_allowed').eq('id', uid).maybeSingle();
    if (me?['is_allowed'] != true) return null;

    final existing = await sb.from('duo_chat').select().or('user_one.eq.$uid,user_two.eq.$uid').limit(1);
    if (existing.isNotEmpty) return existing.first['id'].toString();

    final partners = await sb.from('profiles').select('id').eq('is_allowed', true).neq('id', uid).limit(1);
    if (partners.isEmpty) return null;

    final created = await sb.from('duo_chat').insert({'user_one': uid, 'user_two': partners.first['id']}).select().single();
    return created['id'].toString();
  }

  Future<Map<String, dynamic>?> otherProfile(String chatId) async {
    final chat = await sb.from('duo_chat').select('user_one,user_two').eq('id', chatId).single();
    final otherId = chat['user_one'] == uid ? chat['user_two'] : chat['user_one'];
    return sb.from('profiles').select().eq('id', otherId).maybeSingle();
  }

  Future<SecretKey> key(String chatId) async {
    final other = await otherProfile(chatId);
    final pub = other?['public_key']?.toString();
    if (pub == null || pub.isEmpty) throw Exception('O outro usuário ainda não tem chave pública.');
    return crypto.sharedKey(pub, chatId);
  }

  Stream<List<Map<String, dynamic>>> messages(String chatId) {
    return sb.from('messages').stream(primaryKey: ['id']).eq('chat_id', chatId).order('created_at').map(
          (rows) => rows.map((row) => Map<String, dynamic>.from(row)).toList(),
        );
  }

  Future<void> sendText(String chatId, String text) async {
    final clean = text.trim();
    if (clean.isEmpty) return;
    final encrypted = await crypto.encryptText(clean, await key(chatId));
    await sb.from('messages').insert({'chat_id': chatId, 'sender_id': uid, 'type': 'text', ...encrypted});
    await sb.from('duo_chat').update({'updated_at': DateTime.now().toIso8601String()}).eq('id', chatId);
  }

  Future<void> sendMedia(String chatId, String type, XFile file) async {
    final bytes = await file.readAsBytes();
    final encrypted = await crypto.encryptBytes(bytes, await key(chatId));
    final safeName = p.basename(file.path.isEmpty ? file.name : file.path);
    final storagePath = 'duo/$chatId/${DateTime.now().microsecondsSinceEpoch}_$type.enc';

    await sb.storage.from('chat-media').uploadBinary(
          storagePath,
          encrypted.bytes,
          fileOptions: const FileOptions(contentType: 'application/octet-stream', upsert: false),
        );

    await sb.from('messages').insert({
      'chat_id': chatId,
      'sender_id': uid,
      'type': type,
      'nonce': encrypted.nonce,
      'mac': encrypted.mac,
      'media_path': storagePath,
      'file_name': safeName,
      'mime_type': file.mimeType ?? type,
      'file_size': bytes.length,
    });
    await sb.from('duo_chat').update({'updated_at': DateTime.now().toIso8601String()}).eq('id', chatId);
  }

  Future<Uint8List> downloadMedia(String chatId, Map<String, dynamic> message) async {
    final storagePath = message['media_path']?.toString();
    if (storagePath == null || storagePath.isEmpty) throw Exception('Mídia sem caminho no Storage.');
    final encrypted = await sb.storage.from('chat-media').download(storagePath);
    return crypto.decryptBytes(Uint8List.fromList(encrypted), message['nonce'].toString(), message['mac'].toString(), await key(chatId));
  }

  Future<String> decrypt(String chatId, Map<String, dynamic> message) async {
    try {
      return await crypto.decryptText(message, await key(chatId));
    } catch (_) {
      return 'Não foi possível descriptografar.';
    }
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final email = TextEditingController();
  final pass = TextEditingController();
  final auth = AuthService();
  bool loading = false;

  @override
  void dispose() {
    email.dispose();
    pass.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    setState(() => loading = true);
    try {
      await auth.login(email.text.trim(), pass.text);
    } catch (e) {
      if (mounted) toast(context, 'Erro: $e');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DuoBackground(
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              child: GlassCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Container(
                      width: 88,
                      height: 88,
                      decoration: BoxDecoration(borderRadius: BorderRadius.circular(30), gradient: const LinearGradient(colors: [Color(0xFF6C63FF), Color(0xFF00E5FF)])),
                      child: const Icon(Icons.shield_rounded, size: 46),
                    ),
                    const SizedBox(height: 20),
                    Text('Chat Duo Secure', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w900)),
                    const SizedBox(height: 8),
                    Text('Privado, moderno e criptografado.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withOpacity(.7))),
                    const SizedBox(height: 28),
                    TextField(controller: email, decoration: field('E-mail', Icons.alternate_email_rounded)),
                    const SizedBox(height: 12),
                    TextField(controller: pass, obscureText: true, decoration: field('Senha', Icons.lock_rounded)),
                    const SizedBox(height: 18),
                    FilledButton.icon(onPressed: loading ? null : submit, icon: loading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.arrow_forward_rounded), label: const Text('Entrar')),
                    TextButton(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const RegisterPage())), child: const Text('Criar conta')),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class RegisterPage extends StatefulWidget {
  const RegisterPage({super.key});
  @override
  State<RegisterPage> createState() => _RegisterPageState();
}

class _RegisterPageState extends State<RegisterPage> {
  final name = TextEditingController();
  final email = TextEditingController();
  final pass = TextEditingController();
  final auth = AuthService();
  bool loading = false;

  @override
  void dispose() {
    name.dispose();
    email.dispose();
    pass.dispose();
    super.dispose();
  }

  Future<void> submit() async {
    setState(() => loading = true);
    try {
      await auth.register(name.text.trim(), email.text.trim(), pass.text);
      if (mounted) {
        Navigator.pop(context);
        toast(context, 'Conta criada. Agora libere no Supabase.');
      }
    } catch (e) {
      if (mounted) toast(context, 'Erro: $e');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DuoBackground(
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              child: GlassCard(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(children: [IconButton(onPressed: () => Navigator.pop(context), icon: const Icon(Icons.arrow_back_rounded)), Text('Criar conta', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900))]),
                    const SizedBox(height: 18),
                    TextField(controller: name, decoration: field('Nome', Icons.person_rounded)),
                    const SizedBox(height: 12),
                    TextField(controller: email, decoration: field('E-mail', Icons.alternate_email_rounded)),
                    const SizedBox(height: 12),
                    TextField(controller: pass, obscureText: true, decoration: field('Senha', Icons.lock_rounded)),
                    const SizedBox(height: 18),
                    FilledButton.icon(onPressed: loading ? null : submit, icon: loading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.verified_user_rounded), label: const Text('Cadastrar')),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});
  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final auth = AuthService();
  final chat = ChatService();

  Future<Map<String, dynamic>?> profile() async {
    await auth.syncProfile();
    return sb.from('profiles').select().eq('id', uid).maybeSingle();
  }

  Future<void> openChat() async {
    final chatId = await chat.ensureChat();
    if (!mounted) return;
    if (chatId == null) {
      toast(context, 'Libere os dois usuários no Supabase primeiro.');
      return;
    }
    Navigator.push(context, MaterialPageRoute(builder: (_) => ChatPage(chatId: chatId)));
  }

  void openCall(bool video) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => CallPage(video: video)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DuoBackground(
        child: SafeArea(
          child: FutureBuilder<Map<String, dynamic>?>(
            future: profile(),
            builder: (context, snap) {
              final pData = snap.data;
              final allowed = pData?['is_allowed'] == true;
              final name = pData?['name']?.toString();
              return Padding(
                padding: const EdgeInsets.all(18),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        CircleAvatar(radius: 28, backgroundColor: const Color(0xFF6C63FF), child: Text(firstLetter(name))),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text('Olá, ${name ?? 'Usuário'}', style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w900)),
                              Text(allowed ? 'Acesso liberado' : 'Aguardando liberação', style: TextStyle(color: allowed ? const Color(0xFF71F7A5) : const Color(0xFFFFD166))),
                            ],
                          ),
                        ),
                        IconButton(onPressed: () => auth.logout(), icon: const Icon(Icons.logout_rounded)),
                      ],
                    ),
                    const SizedBox(height: 24),
                    GlassCard(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text('Duo privado', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
                          const SizedBox(height: 8),
                          Text('Chat criptografado para duas pessoas, com texto, foto, vídeo e áudio protegido.', style: TextStyle(color: Colors.white.withOpacity(.7))),
                          const SizedBox(height: 18),
                          Row(
                            children: [
                              Expanded(child: ActionTile(icon: Icons.chat_bubble_rounded, title: 'Chat', sub: 'E2EE', onTap: allowed ? openChat : null)),
                              const SizedBox(width: 12),
                              Expanded(child: ActionTile(icon: Icons.call_rounded, title: 'Áudio', sub: 'WebRTC', onTap: allowed ? () => openCall(false) : null)),
                            ],
                          ),
                          const SizedBox(height: 12),
                          ActionWide(icon: Icons.videocam_rounded, title: 'Chamada de vídeo', sub: 'Tela preparada para evolução WebRTC.', onTap: allowed ? () => openCall(true) : null),
                        ],
                      ),
                    ),
                    const SizedBox(height: 14),
                    GlassCard(child: Row(children: [const Icon(Icons.key_rounded, color: Color(0xFF00E5FF)), const SizedBox(width: 12), Expanded(child: Text('Sua chave privada fica somente no aparelho.', style: TextStyle(color: Colors.white.withOpacity(.7))))])),
                  ],
                ),
              );
            },
          ),
        ),
      ),
    );
  }
}

class ActionTile extends StatelessWidget {
  const ActionTile({super.key, required this.icon, required this.title, required this.sub, this.onTap});
  final IconData icon;
  final String title;
  final String sub;
  final VoidCallback? onTap;
  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(22),
      child: Opacity(
        opacity: onTap == null ? .45 : 1,
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(color: Colors.white.withOpacity(.08), borderRadius: BorderRadius.circular(22), border: Border.all(color: Colors.white.withOpacity(.1))),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Icon(icon, size: 30), const SizedBox(height: 16), Text(title, style: const TextStyle(fontWeight: FontWeight.w900)), Text(sub, style: TextStyle(color: Colors.white.withOpacity(.6)))]),
        ),
      ),
    );
  }
}

class ActionWide extends StatelessWidget {
  const ActionWide({super.key, required this.icon, required this.title, required this.sub, this.onTap});
  final IconData icon;
  final String title;
  final String sub;
  final VoidCallback? onTap;
  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(22),
      child: Opacity(
        opacity: onTap == null ? .45 : 1,
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            gradient: LinearGradient(colors: [const Color(0xFF6C63FF).withOpacity(.55), const Color(0xFF00E5FF).withOpacity(.18)]),
            borderRadius: BorderRadius.circular(22),
            border: Border.all(color: Colors.white.withOpacity(.1)),
          ),
          child: Row(children: [Icon(icon, size: 34), const SizedBox(width: 12), Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(title, style: const TextStyle(fontWeight: FontWeight.w900)), Text(sub, style: TextStyle(color: Colors.white.withOpacity(.68)))])), const Icon(Icons.arrow_forward_ios_rounded, size: 16)]),
        ),
      ),
    );
  }
}

class ChatPage extends StatefulWidget {
  const ChatPage({super.key, required this.chatId});
  final String chatId;
  @override
  State<ChatPage> createState() => _ChatPageState();
}

class _ChatPageState extends State<ChatPage> {
  final controller = TextEditingController();
  final scroll = ScrollController();
  final chat = ChatService();
  final picker = ImagePicker();
  final recorder = AudioRecorder();
  bool sending = false;
  bool menuOpen = false;
  bool recording = false;

  @override
  void dispose() {
    controller.dispose();
    scroll.dispose();
    recorder.dispose();
    super.dispose();
  }

  Future<void> send() async {
    if (sending) return;
    final text = controller.text;
    controller.clear();
    setState(() => sending = true);
    try {
      await chat.sendText(widget.chatId, text);
    } catch (e) {
      if (mounted) toast(context, 'Erro: $e');
    } finally {
      if (mounted) setState(() => sending = false);
    }
  }

  Future<void> sendImage() async {
    final file = await picker.pickImage(source: ImageSource.gallery, imageQuality: 86);
    if (file == null) return;
    if (mounted) setState(() => menuOpen = false);
    try {
      await chat.sendMedia(widget.chatId, 'image', file);
    } catch (e) {
      if (mounted) toast(context, 'Erro ao enviar foto: $e');
    }
  }

  Future<void> sendVideo() async {
    final file = await picker.pickVideo(source: ImageSource.gallery);
    if (file == null) return;
    if (mounted) setState(() => menuOpen = false);
    try {
      await chat.sendMedia(widget.chatId, 'video', file);
    } catch (e) {
      if (mounted) toast(context, 'Erro ao enviar vídeo: $e');
    }
  }

  Future<void> toggleVoice() async {
    if (recording) {
      final path = await recorder.stop();
      setState(() => recording = false);
      if (path == null) return;
      try {
        await chat.sendMedia(widget.chatId, 'audio', XFile(path, name: p.basename(path), mimeType: 'audio/aac'));
      } catch (e) {
        if (mounted) toast(context, 'Erro ao enviar áudio: $e');
      }
      return;
    }

    final permitted = await recorder.hasPermission();
    if (!permitted) {
      if (mounted) toast(context, 'Permita o uso do microfone para gravar áudio.');
      return;
    }
    final dir = await getTemporaryDirectory();
    final path = '${dir.path}/duo_voice_${DateTime.now().millisecondsSinceEpoch}.m4a';
    await recorder.start(const RecordConfig(encoder: AudioEncoder.aacLc), path: path);
    if (mounted) setState(() => recording = true);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DuoBackground(
        child: SafeArea(
          child: Column(
            children: [
              FutureBuilder<Map<String, dynamic>?>(
                future: chat.otherProfile(widget.chatId),
                builder: (context, snap) {
                  final name = snap.data?['name']?.toString() ?? 'Duo privado';
                  return Container(
                    padding: const EdgeInsets.all(10),
                    color: Colors.black.withOpacity(.18),
                    child: Row(
                      children: [
                        IconButton(onPressed: () => Navigator.pop(context), icon: const Icon(Icons.arrow_back_rounded)),
                        CircleAvatar(backgroundColor: const Color(0xFF6C63FF), child: Text(firstLetter(name))),
                        const SizedBox(width: 12),
                        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(name, style: const TextStyle(fontWeight: FontWeight.w900)), Text('criptografia ponta a ponta', style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(.65)))])),
                        IconButton.filledTonal(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const CallPage(video: false))), icon: const Icon(Icons.call_rounded)),
                        const SizedBox(width: 8),
                        IconButton.filled(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const CallPage(video: true))), icon: const Icon(Icons.videocam_rounded)),
                      ],
                    ),
                  );
                },
              ),
              Expanded(
                child: StreamBuilder<List<Map<String, dynamic>>>(
                  stream: chat.messages(widget.chatId),
                  builder: (context, snap) {
                    final messages = snap.data ?? [];
                    if (messages.isEmpty) return const Center(child: Text('Comece a conversa segura 🔐'));
                    return ListView.builder(
                      controller: scroll,
                      padding: const EdgeInsets.symmetric(vertical: 10),
                      itemCount: messages.length,
                      itemBuilder: (context, i) => MessageBubble(chatId: widget.chatId, message: messages[i], chat: chat),
                    );
                  },
                ),
              ),
              AnimatedSwitcher(
                duration: const Duration(milliseconds: 200),
                child: menuOpen
                    ? Container(
                        key: const ValueKey('media-menu'),
                        margin: const EdgeInsets.fromLTRB(12, 0, 12, 8),
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(color: Colors.white.withOpacity(.08), borderRadius: BorderRadius.circular(22)),
                        child: Row(
                          children: [
                            Expanded(child: FilledButton.tonalIcon(onPressed: sendImage, icon: const Icon(Icons.image_rounded), label: const Text('Foto'))),
                            const SizedBox(width: 10),
                            Expanded(child: FilledButton.tonalIcon(onPressed: sendVideo, icon: const Icon(Icons.movie_rounded), label: const Text('Vídeo'))),
                          ],
                        ),
                      )
                    : const SizedBox.shrink(),
              ),
              Container(
                padding: const EdgeInsets.all(10),
                color: Colors.black.withOpacity(.22),
                child: Row(
                  children: [
                    IconButton.filledTonal(onPressed: () => setState(() => menuOpen = !menuOpen), icon: Icon(menuOpen ? Icons.close_rounded : Icons.add_rounded)),
                    const SizedBox(width: 8),
                    Expanded(child: TextField(controller: controller, minLines: 1, maxLines: 4, decoration: field('Mensagem criptografada...', Icons.lock_rounded), onSubmitted: (_) => send())),
                    const SizedBox(width: 8),
                    IconButton.filledTonal(onPressed: toggleVoice, icon: Icon(recording ? Icons.stop_rounded : Icons.mic_rounded, color: recording ? Colors.redAccent : null)),
                    const SizedBox(width: 8),
                    IconButton.filled(onPressed: sending ? null : send, icon: sending ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.send_rounded)),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class MessageBubble extends StatefulWidget {
  const MessageBubble({super.key, required this.chatId, required this.message, required this.chat});
  final String chatId;
  final Map<String, dynamic> message;
  final ChatService chat;

  @override
  State<MessageBubble> createState() => _MessageBubbleState();
}

class _MessageBubbleState extends State<MessageBubble> {
  Uint8List? image;
  bool loading = false;
  AudioPlayer? player;

  bool get mine => widget.message['sender_id'] == uid;

  @override
  void dispose() {
    player?.dispose();
    super.dispose();
  }

  Future<void> openMedia() async {
    setState(() => loading = true);
    try {
      final bytes = await widget.chat.downloadMedia(widget.chatId, widget.message);
      final type = widget.message['type']?.toString() ?? '';
      if (type == 'image') {
        setState(() => image = bytes);
      } else {
        final dir = await getTemporaryDirectory();
        final name = widget.message['file_name']?.toString() ?? 'media.bin';
        final file = File('${dir.path}/$name');
        await file.writeAsBytes(bytes);
        if (type == 'audio') {
          player ??= AudioPlayer();
          await player!.setFilePath(file.path);
          await player!.play();
        } else {
          if (mounted) toast(context, 'Vídeo descriptografado em: ${file.path}');
        }
      }
    } catch (e) {
      if (mounted) toast(context, 'Erro ao abrir mídia: $e');
    } finally {
      if (mounted) setState(() => loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final type = widget.message['type']?.toString() ?? 'text';
    final isText = type == 'text';
    final icon = type == 'audio' ? Icons.graphic_eq_rounded : type == 'video' ? Icons.movie_rounded : Icons.image_rounded;
    final label = type == 'audio' ? 'Tocar áudio' : type == 'video' ? 'Abrir vídeo' : 'Abrir foto';

    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: BoxConstraints(maxWidth: MediaQuery.sizeOf(context).width * .78),
        margin: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          gradient: mine ? const LinearGradient(colors: [Color(0xFF6C63FF), Color(0xFF5148D9)]) : null,
          color: mine ? null : Colors.white.withOpacity(.09),
          borderRadius: BorderRadius.only(topLeft: const Radius.circular(22), topRight: const Radius.circular(22), bottomLeft: Radius.circular(mine ? 22 : 6), bottomRight: Radius.circular(mine ? 6 : 22)),
        ),
        child: isText
            ? FutureBuilder<String>(future: widget.chat.decrypt(widget.chatId, widget.message), builder: (context, snap) => Text(snap.data ?? '...', style: const TextStyle(fontSize: 15.5)))
            : Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (image != null)
                    ClipRRect(borderRadius: BorderRadius.circular(16), child: Image.memory(image!, fit: BoxFit.cover))
                  else ...[
                    Row(mainAxisSize: MainAxisSize.min, children: [Icon(icon), const SizedBox(width: 8), Flexible(child: Text(widget.message['file_name']?.toString() ?? 'mídia criptografada', overflow: TextOverflow.ellipsis))]),
                    const SizedBox(height: 8),
                    FilledButton.tonalIcon(onPressed: loading ? null : openMedia, icon: loading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : Icon(type == 'audio' ? Icons.play_arrow_rounded : Icons.lock_open_rounded), label: Text(label)),
                  ],
                ],
              ),
      ),
    );
  }
}

class CallPage extends StatelessWidget {
  const CallPage({super.key, required this.video});
  final bool video;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: DuoBackground(
        child: SafeArea(
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              children: [
                Row(children: [IconButton(onPressed: () => Navigator.pop(context), icon: const Icon(Icons.arrow_back_rounded)), Expanded(child: Text(video ? 'Chamada de vídeo' : 'Chamada de áudio', style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w900))), const Icon(Icons.lock_rounded)]),
                const SizedBox(height: 20),
                Expanded(
                  child: Container(
                    width: double.infinity,
                    decoration: BoxDecoration(color: Colors.black.withOpacity(.35), borderRadius: BorderRadius.circular(32), border: Border.all(color: Colors.white.withOpacity(.1))),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(video ? Icons.videocam_rounded : Icons.graphic_eq_rounded, size: 120),
                        const SizedBox(height: 18),
                        Text(video ? 'Base de vídeo pronta' : 'Base de áudio pronta', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
                        const SizedBox(height: 8),
                        Padding(padding: const EdgeInsets.symmetric(horizontal: 28), child: Text('O próximo update completa a negociação WebRTC de aceitar/recusar chamada.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withOpacity(.7)))),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 20),
                FilledButton.icon(onPressed: () => Navigator.pop(context), icon: const Icon(Icons.call_end_rounded), label: const Text('Encerrar')),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
