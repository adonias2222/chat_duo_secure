import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:intl/intl.dart';
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

void toast(BuildContext context, String text) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
}

String firstLetter(String? value) {
  final clean = (value ?? '').trim();
  return clean.isEmpty ? 'U' : clean.characters.first.toUpperCase();
}

DateTime? parseDate(dynamic value) => DateTime.tryParse(value?.toString() ?? '')?.toLocal();

String hourOf(dynamic value) {
  final date = parseDate(value);
  return date == null ? '' : DateFormat('HH:mm').format(date);
}

String dayLabel(DateTime date) {
  final now = DateTime.now();
  final today = DateTime(now.year, now.month, now.day);
  final day = DateTime(date.year, date.month, date.day);
  final diff = today.difference(day).inDays;
  if (diff == 0) return 'Hoje';
  if (diff == 1) return 'Ontem';
  return DateFormat('dd/MM/yyyy').format(date);
}

InputDecoration input(String label, IconData icon) {
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
      builder: (context, snapshot) => sb.auth.currentSession == null ? const LoginPage() : const HomePage(),
    );
  }
}

class Background extends StatelessWidget {
  const Background({super.key, required this.child});
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
      child: child,
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

class SetupPage extends StatelessWidget {
  const SetupPage({super.key});

  @override
  Widget build(BuildContext context) {
    return const Scaffold(
      body: Background(
        child: Center(
          child: GlassCard(
            child: Text('Configure SUPABASE_URL e SUPABASE_ANON_KEY nos Secrets do GitHub Actions.'),
          ),
        ),
      ),
    );
  }
}

class CryptoService {
  CryptoService._();
  static final instance = CryptoService._();
  final _secure = const FlutterSecureStorage();
  final _aes = AesGcm.with256bits();

  String _storageKey(String chatId) => 'manual_chat_secret_$chatId';

  Future<bool> hasSecret(String chatId) async {
    final value = await _secure.read(key: _storageKey(chatId));
    return value != null && value.trim().isNotEmpty;
  }

  Future<void> saveSecret(String chatId, String value) async {
    final clean = value.trim();
    if (clean.length < 4) throw Exception('Use uma chave com pelo menos 4 caracteres.');
    await _secure.write(key: _storageKey(chatId), value: clean);
  }

  Future<SecretKey> key(String chatId) async {
    final phrase = await _secure.read(key: _storageKey(chatId));
    if (phrase == null || phrase.trim().isEmpty) {
      throw Exception('Defina a chave do chat.');
    }
    final pbkdf2 = Pbkdf2(macAlgorithm: Hmac.sha256(), iterations: 120000, bits: 256);
    return pbkdf2.deriveKeyFromPassword(
      password: phrase.trim(),
      nonce: utf8.encode('chat-duo-secure-v2:$chatId'),
    );
  }

  Future<Map<String, String>> encryptText(String text, String chatId) async {
    final box = await _aes.encrypt(utf8.encode(text), secretKey: await key(chatId));
    return {
      'cipher_text': base64Encode(box.cipherText),
      'nonce': base64Encode(box.nonce),
      'mac': base64Encode(box.mac.bytes),
    };
  }

  Future<String> decryptText(Map<String, dynamic> msg, String chatId) async {
    final clear = await _aes.decrypt(
      SecretBox(
        base64Decode(msg['cipher_text']?.toString() ?? ''),
        nonce: base64Decode(msg['nonce']?.toString() ?? ''),
        mac: Mac(base64Decode(msg['mac']?.toString() ?? '')),
      ),
      secretKey: await key(chatId),
    );
    return utf8.decode(clear);
  }
}

class AuthService {
  Future<void> syncProfile({String fallbackName = 'Usuário'}) async {
    final user = sb.auth.currentUser;
    if (user == null) return;
    await sb.from('profiles').upsert({
      'id': user.id,
      'name': (user.userMetadata?['name'] as String?) ?? fallbackName,
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
  final crypto = CryptoService.instance;

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

  Future<bool> hasSecret(String chatId) => crypto.hasSecret(chatId);

  Future<void> saveSecret(String chatId, String value) => crypto.saveSecret(chatId, value);

  Stream<List<Map<String, dynamic>>> messages(String chatId) {
    return sb.from('messages').stream(primaryKey: ['id']).eq('chat_id', chatId).order('created_at').map((rows) {
      final list = rows.map((row) => Map<String, dynamic>.from(row)).toList();
      list.sort((a, b) {
        final da = parseDate(a['created_at']) ?? DateTime.fromMillisecondsSinceEpoch(0);
        final db = parseDate(b['created_at']) ?? DateTime.fromMillisecondsSinceEpoch(0);
        return da.compareTo(db);
      });
      return list.length > 120 ? list.sublist(list.length - 120) : list;
    });
  }

  Future<void> sendText(String chatId, String text) async {
    final clean = text.trim();
    if (clean.isEmpty) return;
    final encrypted = await crypto.encryptText(clean, chatId);
    await sb.from('messages').insert({'chat_id': chatId, 'sender_id': uid, 'type': 'text', ...encrypted});
    await sb.from('duo_chat').update({'updated_at': DateTime.now().toIso8601String()}).eq('id', chatId);
  }

  Future<String> decrypt(String chatId, Map<String, dynamic> msg) async {
    if (msg['type'] != 'text') return 'Mídia protegida. Reativaremos mídia na próxima etapa.';
    try {
      return await crypto.decryptText(msg, chatId);
    } catch (_) {
      return 'Mensagem antiga ou chave diferente.';
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
      body: Background(
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              child: GlassCard(
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Container(width: 88, height: 88, decoration: BoxDecoration(borderRadius: BorderRadius.circular(30), gradient: const LinearGradient(colors: [Color(0xFF6C63FF), Color(0xFF00E5FF)])), child: const Icon(Icons.shield_rounded, size: 46)),
                  const SizedBox(height: 20),
                  Text('Chat Duo Secure', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w900)),
                  const SizedBox(height: 8),
                  Text('Privado, moderno e criptografado.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withOpacity(.7))),
                  const SizedBox(height: 28),
                  TextField(controller: email, decoration: input('E-mail', Icons.alternate_email_rounded)),
                  const SizedBox(height: 12),
                  TextField(controller: pass, obscureText: true, decoration: input('Senha', Icons.lock_rounded)),
                  const SizedBox(height: 18),
                  FilledButton.icon(onPressed: loading ? null : submit, icon: loading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.arrow_forward_rounded), label: const Text('Entrar')),
                  TextButton(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const RegisterPage())), child: const Text('Criar conta')),
                ]),
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
      body: Background(
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              child: GlassCard(
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Row(children: [IconButton(onPressed: () => Navigator.pop(context), icon: const Icon(Icons.arrow_back_rounded)), Text('Criar conta', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900))]),
                  const SizedBox(height: 18),
                  TextField(controller: name, decoration: input('Nome', Icons.person_rounded)),
                  const SizedBox(height: 12),
                  TextField(controller: email, decoration: input('E-mail', Icons.alternate_email_rounded)),
                  const SizedBox(height: 12),
                  TextField(controller: pass, obscureText: true, decoration: input('Senha', Icons.lock_rounded)),
                  const SizedBox(height: 18),
                  FilledButton.icon(onPressed: loading ? null : submit, icon: loading ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.verified_user_rounded), label: const Text('Cadastrar')),
                ]),
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

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Background(
        child: SafeArea(
          child: FutureBuilder<Map<String, dynamic>?>(
            future: profile(),
            builder: (context, snap) {
              final p = snap.data;
              final allowed = p?['is_allowed'] == true;
              final name = p?['name']?.toString();
              return Padding(
                padding: const EdgeInsets.all(18),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    CircleAvatar(radius: 28, backgroundColor: const Color(0xFF6C63FF), child: Text(firstLetter(name))),
                    const SizedBox(width: 14),
                    Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text('Olá, ${name ?? 'Usuário'}', style: Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w900)), Text(allowed ? 'Acesso liberado' : 'Aguardando liberação', style: TextStyle(color: allowed ? const Color(0xFF71F7A5) : const Color(0xFFFFD166)))])),
                    IconButton(onPressed: () => auth.logout(), icon: const Icon(Icons.logout_rounded)),
                  ]),
                  const SizedBox(height: 24),
                  GlassCard(
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text('Duo privado', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
                      const SizedBox(height: 8),
                      Text('Use a mesma chave do chat nos dois celulares para descriptografar as mensagens novas.', style: TextStyle(color: Colors.white.withOpacity(.7))),
                      const SizedBox(height: 18),
                      Row(children: [Expanded(child: ActionTile(icon: Icons.chat_bubble_rounded, title: 'Chat', sub: 'E2EE', onTap: allowed ? openChat : null)), const SizedBox(width: 12), Expanded(child: ActionTile(icon: Icons.call_rounded, title: 'Áudio', sub: 'em breve', onTap: allowed ? () => toast(context, 'Chamadas entram na próxima etapa.') : null))]),
                    ]),
                  ),
                ]),
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

class ChatPage extends StatefulWidget {
  const ChatPage({super.key, required this.chatId});
  final String chatId;
  @override
  State<ChatPage> createState() => _ChatPageState();
}

class _ChatPageState extends State<ChatPage> {
  final controller = TextEditingController();
  final secretController = TextEditingController();
  final scroll = ScrollController();
  final chat = ChatService();
  bool sending = false;
  bool secretReady = false;
  int messageCount = 0;

  @override
  void initState() {
    super.initState();
    checkSecret();
  }

  @override
  void dispose() {
    controller.dispose();
    secretController.dispose();
    scroll.dispose();
    super.dispose();
  }

  Future<void> checkSecret() async {
    final ok = await chat.hasSecret(widget.chatId);
    if (mounted) setState(() => secretReady = ok);
  }

  Future<void> saveSecretFromInput() async {
    try {
      await chat.saveSecret(widget.chatId, secretController.text);
      secretController.clear();
      await checkSecret();
      if (mounted) toast(context, 'Chave salva neste aparelho.');
    } catch (e) {
      if (mounted) toast(context, '$e');
    }
  }

  Future<bool> requireSecret() async {
    if (await chat.hasSecret(widget.chatId)) return true;
    if (mounted) toast(context, 'Digite e salve a chave do chat primeiro.');
    return false;
  }

  void scrollBottom({bool force = false}) {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!scroll.hasClients) return;
      final nearBottom = scroll.position.maxScrollExtent - scroll.offset < 260;
      if (force || nearBottom) {
        scroll.animateTo(scroll.position.maxScrollExtent, duration: const Duration(milliseconds: 250), curve: Curves.easeOut);
      }
    });
  }

  Future<void> send() async {
    if (sending) return;
    if (!await requireSecret()) return;
    final text = controller.text;
    controller.clear();
    setState(() => sending = true);
    try {
      await chat.sendText(widget.chatId, text);
      scrollBottom(force: true);
    } catch (e) {
      if (mounted) toast(context, 'Erro: $e');
    } finally {
      if (mounted) setState(() => sending = false);
    }
  }

  List<Widget> buildTimeline(List<Map<String, dynamic>> messages) {
    final widgets = <Widget>[];
    DateTime? lastDay;
    for (final msg in messages) {
      final date = parseDate(msg['created_at']);
      if (date != null) {
        final day = DateTime(date.year, date.month, date.day);
        if (lastDay == null || day != lastDay) {
          widgets.add(DateChip(label: dayLabel(date)));
          lastDay = day;
        }
      }
      widgets.add(MessageBubble(chatId: widget.chatId, message: msg, chat: chat));
    }
    return widgets;
  }

  Widget secretPanel() {
    if (secretReady) return const SizedBox.shrink();
    return Container(
      margin: const EdgeInsets.fromLTRB(12, 10, 12, 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(color: const Color(0xFFFFD166).withOpacity(.12), borderRadius: BorderRadius.circular(22), border: Border.all(color: const Color(0xFFFFD166).withOpacity(.35))),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Defina a chave do chat', style: TextStyle(fontWeight: FontWeight.w900)),
        const SizedBox(height: 6),
        Text('Coloque exatamente a mesma chave nos dois celulares. Ela fica salva só no aparelho.', style: TextStyle(color: Colors.white.withOpacity(.75), fontSize: 12)),
        const SizedBox(height: 10),
        Row(children: [
          Expanded(child: TextField(controller: secretController, obscureText: true, decoration: input('Chave combinada', Icons.key_rounded))),
          const SizedBox(width: 8),
          IconButton.filled(onPressed: saveSecretFromInput, icon: const Icon(Icons.check_rounded)),
        ]),
      ]),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Background(
        child: SafeArea(
          child: Column(children: [
            FutureBuilder<Map<String, dynamic>?>(
              future: chat.otherProfile(widget.chatId),
              builder: (context, snap) {
                final name = snap.data?['name']?.toString() ?? 'Duo privado';
                return Container(
                  padding: const EdgeInsets.all(10),
                  color: Colors.black.withOpacity(.18),
                  child: Row(children: [
                    IconButton(onPressed: () => Navigator.pop(context), icon: const Icon(Icons.arrow_back_rounded)),
                    CircleAvatar(backgroundColor: const Color(0xFF6C63FF), child: Text(firstLetter(name))),
                    const SizedBox(width: 12),
                    Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(name, style: const TextStyle(fontWeight: FontWeight.w900)), Text(secretReady ? 'chave local ativa' : 'defina a chave do chat', style: TextStyle(fontSize: 12, color: secretReady ? const Color(0xFF71F7A5) : const Color(0xFFFFD166)))])),
                    IconButton.filledTonal(onPressed: () => setState(() => secretReady = false), icon: const Icon(Icons.key_rounded)),
                  ]),
                );
              },
            ),
            secretPanel(),
            Expanded(
              child: StreamBuilder<List<Map<String, dynamic>>>(
                stream: chat.messages(widget.chatId),
                builder: (context, snap) {
                  final messages = snap.data ?? [];
                  if (messages.length != messageCount) {
                    messageCount = messages.length;
                    scrollBottom();
                  }
                  if (messages.isEmpty) return const Center(child: Text('Comece a conversa segura 🔐'));
                  return ListView(controller: scroll, padding: const EdgeInsets.symmetric(vertical: 10), children: buildTimeline(messages));
                },
              ),
            ),
            Container(
              padding: const EdgeInsets.all(10),
              color: Colors.black.withOpacity(.22),
              child: Row(children: [
                IconButton.filledTonal(onPressed: () => toast(context, 'Foto, vídeo e áudio serão reativados na próxima etapa.'), icon: const Icon(Icons.add_rounded)),
                const SizedBox(width: 8),
                Expanded(child: TextField(controller: controller, minLines: 1, maxLines: 4, decoration: input('Mensagem criptografada...', Icons.lock_rounded), onSubmitted: (_) => send())),
                const SizedBox(width: 8),
                IconButton.filled(onPressed: sending ? null : send, icon: sending ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.send_rounded)),
              ]),
            ),
          ]),
        ),
      ),
    );
  }
}

class DateChip extends StatelessWidget {
  const DateChip({super.key, required this.label});
  final String label;
  @override
  Widget build(BuildContext context) {
    return Center(child: Container(margin: const EdgeInsets.symmetric(vertical: 10), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6), decoration: BoxDecoration(color: Colors.black.withOpacity(.35), borderRadius: BorderRadius.circular(999), border: Border.all(color: Colors.white.withOpacity(.08))), child: Text(label, style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(.75), fontWeight: FontWeight.w700))));
  }
}

class MessageBubble extends StatelessWidget {
  const MessageBubble({super.key, required this.chatId, required this.message, required this.chat});
  final String chatId;
  final Map<String, dynamic> message;
  final ChatService chat;

  bool get mine => message['sender_id'] == uid;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: mine ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        constraints: BoxConstraints(maxWidth: MediaQuery.sizeOf(context).width * .78),
        margin: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          gradient: mine ? const LinearGradient(colors: [Color(0xFF6C63FF), Color(0xFF5148D9)]) : null,
          color: mine ? null : Colors.white.withOpacity(.09),
          borderRadius: BorderRadius.only(topLeft: const Radius.circular(22), topRight: const Radius.circular(22), bottomLeft: Radius.circular(mine ? 22 : 6), bottomRight: Radius.circular(mine ? 6 : 22)),
        ),
        child: Column(crossAxisAlignment: mine ? CrossAxisAlignment.end : CrossAxisAlignment.start, children: [
          FutureBuilder<String>(future: chat.decrypt(chatId, message), builder: (context, snap) => Text(snap.data ?? '...', style: const TextStyle(fontSize: 15.5))),
          const SizedBox(height: 4),
          Row(mainAxisSize: MainAxisSize.min, children: [const Icon(Icons.lock_rounded, size: 12), const SizedBox(width: 4), Text(hourOf(message['created_at']), style: TextStyle(fontSize: 11, color: Colors.white.withOpacity(.7)))]),
        ]),
      ),
    );
  }
}
