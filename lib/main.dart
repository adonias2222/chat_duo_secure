import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';
import 'package:just_audio/just_audio.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:record/record.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

class Env {
  static const supabaseUrl = String.fromEnvironment('SUPABASE_URL');
  static const supabaseAnonKey = String.fromEnvironment('SUPABASE_ANON_KEY');
  static bool get isConfigured => supabaseUrl.isNotEmpty && supabaseAnonKey.isNotEmpty;
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (Env.isConfigured) {
    await Supabase.initialize(url: Env.supabaseUrl, anonKey: Env.supabaseAnonKey, debug: true);
  }
  runApp(const ChatDuoApp());
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

SupabaseClient get sb => Supabase.instance.client;
String get uid => sb.auth.currentUser!.id;

class AuthGate extends StatelessWidget {
  const AuthGate({super.key});

  @override
  Widget build(BuildContext context) {
    if (!Env.isConfigured) return const SetupPage();
    return StreamBuilder<AuthState>(
      stream: sb.auth.onAuthStateChange,
      builder: (_, __) => sb.auth.currentSession == null ? const LoginPage() : const HomePage(),
    );
  }
}

class SetupPage extends StatelessWidget {
  const SetupPage({super.key});
  @override
  Widget build(BuildContext context) => Scaffold(
        body: GradientShell(
          child: Center(
            child: GlassCard(
              child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Icon(Icons.lock_rounded, size: 46),
                const SizedBox(height: 16),
                Text('Configure o Supabase', style: Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight: FontWeight.w900)),
                const SizedBox(height: 10),
                const Text('Passe SUPABASE_URL e SUPABASE_ANON_KEY via --dart-define ou pelos Secrets do GitHub Actions.'),
                const SizedBox(height: 14),
                const SelectableText('flutter run --dart-define=SUPABASE_URL="..." --dart-define=SUPABASE_ANON_KEY="..."'),
              ]),
            ),
          ),
        ),
      );
}

class GradientShell extends StatelessWidget {
  const GradientShell({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [Color(0xFF07111F), Color(0xFF181139), Color(0xFF063847), Color(0xFF070A16)],
          ),
        ),
        child: Stack(children: [
          Positioned(top: -70, left: -50, child: Orb(color: const Color(0xFF6C63FF).withOpacity(.25), size: 220)),
          Positioned(bottom: 80, right: -70, child: Orb(color: const Color(0xFF00E5FF).withOpacity(.16), size: 220)),
          child,
        ]),
      );
}

class Orb extends StatelessWidget {
  const Orb({super.key, required this.color, required this.size});
  final Color color;
  final double size;
  @override
  Widget build(BuildContext context) => Container(
        width: size,
        height: size,
        decoration: BoxDecoration(shape: BoxShape.circle, boxShadow: [BoxShadow(color: color, blurRadius: 100, spreadRadius: 60)]),
      );
}

class GlassCard extends StatelessWidget {
  const GlassCard({super.key, required this.child, this.padding = const EdgeInsets.all(20)});
  final Widget child;
  final EdgeInsetsGeometry padding;
  @override
  Widget build(BuildContext context) => Container(
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

class E2eeService {
  E2eeService._();
  static final instance = E2eeService._();
  final _storage = const FlutterSecureStorage();
  final _x25519 = X25519();
  final _aes = AesGcm.with256bits();
  static const _privateKey = 'duo_private_x25519';
  static const _publicKey = 'duo_public_x25519';

  Future<SimpleKeyPair> keyPair() async {
    final priv = await _storage.read(key: _privateKey);
    final pub = await _storage.read(key: _publicKey);
    if (priv != null && pub != null) {
      return SimpleKeyPairData(base64Decode(priv), publicKey: SimplePublicKey(base64Decode(pub), type: KeyPairType.x25519), type: KeyPairType.x25519);
    }
    final pair = await _x25519.newKeyPair();
    final data = await pair.extract();
    final publicKey = await pair.extractPublicKey();
    await _storage.write(key: _privateKey, value: base64Encode(data.bytes));
    await _storage.write(key: _publicKey, value: base64Encode(publicKey.bytes));
    return pair;
  }

  Future<String> publicKeyBase64() async => base64Encode((await (await keyPair()).extractPublicKey()).bytes);

  Future<SecretKey> sharedKey(String otherPublicKeyBase64, String chatId) async {
    final raw = await _x25519.sharedSecretKey(
      keyPair: await keyPair(),
      remotePublicKey: SimplePublicKey(base64Decode(otherPublicKeyBase64), type: KeyPairType.x25519),
    );
    return Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(secretKey: raw, nonce: utf8.encode(chatId), info: utf8.encode('chat-duo-v1'));
  }

  Future<Map<String, String>> encryptText(String text, SecretKey key) async {
    final box = await _aes.encrypt(utf8.encode(text), secretKey: key);
    return {'cipher_text': base64Encode(box.cipherText), 'nonce': base64Encode(box.nonce), 'mac': base64Encode(box.mac.bytes)};
  }

  Future<String> decryptText(Map<String, dynamic> msg, SecretKey key) async {
    final clear = await _aes.decrypt(
      SecretBox(base64Decode(msg['cipher_text'] ?? ''), nonce: base64Decode(msg['nonce'] ?? ''), mac: Mac(base64Decode(msg['mac'] ?? ''))),
      secretKey: key,
    );
    return utf8.decode(clear);
  }

  Future<({Uint8List bytes, String nonce, String mac})> encryptBytes(Uint8List bytes, SecretKey key) async {
    final box = await _aes.encrypt(bytes, secretKey: key);
    return (bytes: Uint8List.fromList(box.cipherText), nonce: base64Encode(box.nonce), mac: base64Encode(box.mac.bytes));
  }

  Future<Uint8List> decryptBytes(Uint8List bytes, String nonce, String mac, SecretKey key) async {
    final clear = await _aes.decrypt(SecretBox(bytes, nonce: base64Decode(nonce), mac: Mac(base64Decode(mac))), secretKey: key);
    return Uint8List.fromList(clear);
  }
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
    final current = sb.auth.currentUser;
    if (current != null) {
      await sb.from('profiles').update({'online': false, 'last_seen': DateTime.now().toIso8601String()}).eq('id', current.id);
    }
    await sb.auth.signOut();
  }
}

class ChatService {
  final _crypto = E2eeService.instance;

  Future<String?> ensureChat() async {
    final me = await sb.from('profiles').select('is_allowed').eq('id', uid).maybeSingle();
    if (me?['is_allowed'] != true) return null;
    final existing = await sb.from('duo_chat').select().or('user_one.eq.$uid,user_two.eq.$uid').limit(1);
    if (existing is List && existing.isNotEmpty) return existing.first['id'].toString();
    final partner = await sb.from('profiles').select('id').eq('is_allowed', true).neq('id', uid).limit(1);
    if (partner is! List || partner.isEmpty) return null;
    final created = await sb.from('duo_chat').insert({'user_one': uid, 'user_two': partner.first['id']}).select().single();
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
    return _crypto.sharedKey(pub, chatId);
  }

  Stream<List<Map<String, dynamic>>> messages(String chatId) => sb
      .from('messages')
      .stream(primaryKey: ['id'])
      .eq('chat_id', chatId)
      .order('created_at')
      .map((rows) => rows.map((e) => Map<String, dynamic>.from(e)).toList());

  Future<void> sendText(String chatId, String text) async {
    if (text.trim().isEmpty) return;
    final encrypted = await _crypto.encryptText(text.trim(), await key(chatId));
    await sb.from('messages').insert({'chat_id': chatId, 'sender_id': uid, 'type': 'text', ...encrypted});
    await sb.from('duo_chat').update({'updated_at': DateTime.now().toIso8601String()}).eq('id', chatId);
  }

  Future<String> decryptTextSafe(String chatId, Map<String, dynamic> msg) async {
    try {
      return _crypto.decryptText(msg, await key(chatId));
    } catch (_) {
      return 'Não foi possível descriptografar.';
    }
  }

  Future<void> sendMedia(String chatId, String type, XFile file) async {
    final bytes = await file.readAsBytes();
    final encrypted = await _crypto.encryptBytes(bytes, await key(chatId));
    final mediaPath = 'duo/$chatId/${DateTime.now().microsecondsSinceEpoch}.enc';
    await sb.storage.from('chat-media').uploadBinary(mediaPath, encrypted.bytes, fileOptions: const FileOptions(contentType: 'application/octet-stream', upsert: true));
    await sb.from('messages').insert({
      'chat_id': chatId,
      'sender_id': uid,
      'type': type,
      'nonce': encrypted.nonce,
      'mac': encrypted.mac,
      'media_path': mediaPath,
      'file_name': p.basename(file.path),
      'mime_type': file.mimeType,
      'file_size': bytes.length,
    });
  }

  Future<void> sendAudioPath(String chatId, String path) async {
    final file = XFile(path, mimeType: 'audio/aac', name: p.basename(path));
    await sendMedia(chatId, 'audio', file);
  }

  Future<Uint8List> downloadMedia(String chatId, Map<String, dynamic> msg) async {
    final encrypted = await sb.storage.from('chat-media').download(msg['media_path']);
    return _crypto.decryptBytes(Uint8List.fromList(encrypted), msg['nonce'], msg['mac'], await key(chatId));
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});
  @override State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final email = TextEditingController();
  final pass = TextEditingController();
  bool loading = false;
  final auth = AuthService();
  @override void dispose(){email.dispose(); pass.dispose(); super.dispose();}
  Future<void> submit() async {setState(()=>loading=true); try {await auth.login(email.text.trim(), pass.text);} catch(e){if(mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Erro: $e')));} finally {if(mounted) setState(()=>loading=false);}}
  @override Widget build(BuildContext context) => Scaffold(body: GradientShell(child: SafeArea(child: Center(child: SingleChildScrollView(child: GlassCard(child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
    Container(width: 88,height: 88,decoration: BoxDecoration(borderRadius: BorderRadius.circular(30), gradient: const LinearGradient(colors:[Color(0xFF6C63FF), Color(0xFF00E5FF)])), child: const Icon(Icons.shield_rounded, size: 46)),
    const SizedBox(height: 20),
    Text('Chat Duo Secure', textAlign: TextAlign.center, style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.w900)),
    const SizedBox(height: 8),
    Text('Privado, moderno e criptografado.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withOpacity(.7))),
    const SizedBox(height: 28),
    TextField(controller: email, decoration: input('E-mail', Icons.alternate_email_rounded)), const SizedBox(height: 12),
    TextField(controller: pass, obscureText: true, decoration: input('Senha', Icons.lock_rounded)), const SizedBox(height: 18),
    FilledButton.icon(onPressed: loading?null:submit, icon: loading?const SizedBox(width:16,height:16,child:CircularProgressIndicator(strokeWidth:2)):const Icon(Icons.arrow_forward_rounded), label: const Text('Entrar'), style: btn()),
    TextButton(onPressed: ()=>Navigator.push(context, MaterialPageRoute(builder: (_) => const RegisterPage())), child: const Text('Criar conta')),
  ]))))))));
}

InputDecoration input(String label, IconData icon) => InputDecoration(labelText: label, prefixIcon: Icon(icon), filled: true, fillColor: Colors.white.withOpacity(.08), border: OutlineInputBorder(borderRadius: BorderRadius.circular(22), borderSide: BorderSide.none));
ButtonStyle btn() => FilledButton.styleFrom(minimumSize: const Size.fromHeight(54), shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)));

class RegisterPage extends StatefulWidget {const RegisterPage({super.key}); @override State<RegisterPage> createState()=>_RegisterPageState();}
class _RegisterPageState extends State<RegisterPage>{final name=TextEditingController();final email=TextEditingController();final pass=TextEditingController();bool loading=false;final auth=AuthService();@override void dispose(){name.dispose();email.dispose();pass.dispose();super.dispose();}Future<void> submit() async{setState(()=>loading=true);try{await auth.register(name.text.trim(), email.text.trim(), pass.text); if(mounted){Navigator.pop(context); ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Conta criada. Agora libere no Supabase.')));}}catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Erro: $e')));}finally{if(mounted)setState(()=>loading=false);}}@override Widget build(BuildContext context)=>Scaffold(body:GradientShell(child:SafeArea(child:Center(child:SingleChildScrollView(child:GlassCard(child:Column(crossAxisAlignment:CrossAxisAlignment.stretch,children:[Row(children:[IconButton(onPressed:()=>Navigator.pop(context),icon:const Icon(Icons.arrow_back_rounded)),Text('Criar conta',style:Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight:FontWeight.w900))]),const SizedBox(height:18),TextField(controller:name,decoration:input('Nome',Icons.person_rounded)),const SizedBox(height:12),TextField(controller:email,decoration:input('E-mail',Icons.alternate_email_rounded)),const SizedBox(height:12),TextField(controller:pass,obscureText:true,decoration:input('Senha',Icons.lock_rounded)),const SizedBox(height:18),FilledButton.icon(onPressed:loading?null:submit,icon:loading?const SizedBox(width:16,height:16,child:CircularProgressIndicator(strokeWidth:2)):const Icon(Icons.verified_user_rounded),label:const Text('Cadastrar'),style:btn())])))))));}

class HomePage extends StatefulWidget {const HomePage({super.key}); @override State<HomePage> createState()=>_HomePageState();}
class _HomePageState extends State<HomePage>{final chat=ChatService();final auth=AuthService();Future<Map<String,dynamic>?> profile() async{await auth.syncProfile();return sb.from('profiles').select().eq('id', uid).maybeSingle();}Future<void> openChat()async{final id=await chat.ensureChat();if(!mounted)return;if(id==null){ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content:Text('Libere os dois usuários no Supabase primeiro.')));return;}Navigator.push(context,MaterialPageRoute(builder:(_)=>ChatPage(chatId:id)));}Future<void> openCall(bool video)async{final id=await chat.ensureChat();if(!mounted)return;if(id==null)return;Navigator.push(context,MaterialPageRoute(builder:(_)=>CallPage(chatId:id,video:video)));}@override Widget build(BuildContext context)=>Scaffold(body:GradientShell(child:SafeArea(child:FutureBuilder<Map<String,dynamic>?>(future:profile(),builder:(context,s){final p=s.data;final allowed=p?['is_allowed']==true;return Padding(padding:const EdgeInsets.all(18),child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Row(children:[Container(width:56,height:56,decoration:BoxDecoration(borderRadius:BorderRadius.circular(18),gradient:const LinearGradient(colors:[Color(0xFF6C63FF),Color(0xFF00E5FF)])),child:const Icon(Icons.shield_rounded)),const SizedBox(width:14),Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Text('Olá, ${p?['name']??'Usuário'}',style:Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight:FontWeight.w900)),Text(allowed?'Acesso liberado':'Aguardando liberação',style:TextStyle(color:allowed?const Color(0xFF71F7A5):const Color(0xFFFFD166)))])),IconButton(onPressed:()=>auth.logout(),icon:const Icon(Icons.logout_rounded))]),const SizedBox(height:24),GlassCard(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Text('Duo privado',style:Theme.of(context).textTheme.headlineSmall?.copyWith(fontWeight:FontWeight.w900)),const SizedBox(height:8),Text('Chat com texto, foto, vídeo, áudio e base WebRTC para chamadas.',style:TextStyle(color:Colors.white.withOpacity(.7))),const SizedBox(height:18),Row(children:[Expanded(child:ActionTile(icon:Icons.chat_bubble_rounded,title:'Chat',sub:'Tempo real',onTap:allowed?openChat:null)),const SizedBox(width:12),Expanded(child:ActionTile(icon:Icons.call_rounded,title:'Áudio',sub:'WebRTC',onTap:allowed?()=>openCall(false):null))]),const SizedBox(height:12),ActionWide(icon:Icons.videocam_rounded,title:'Chamada de vídeo',sub:'Câmera, microfone e sinalização pelo Supabase.',onTap:allowed?()=>openCall(true):null)])),const SizedBox(height:14),GlassCard(child:Row(children:[const Icon(Icons.key_rounded,color:Color(0xFF00E5FF)),const SizedBox(width:12),Expanded(child:Text('A chave privada fica no aparelho. O Supabase só vê dados criptografados.',style:TextStyle(color:Colors.white.withOpacity(.7))))]))]));}))));}

class ActionTile extends StatelessWidget{const ActionTile({super.key,required this.icon,required this.title,required this.sub,this.onTap});final IconData icon;final String title,sub;final VoidCallback? onTap;@override Widget build(BuildContext context)=>InkWell(onTap:onTap,borderRadius:BorderRadius.circular(22),child:Opacity(opacity:onTap == null ? .45 : 1,child:Container(padding:const EdgeInsets.all(16),decoration:BoxDecoration(color:Colors.white.withOpacity(.08),borderRadius:BorderRadius.circular(22),border:Border.all(color:Colors.white.withOpacity(.1))),child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Icon(icon,size:30),const SizedBox(height:16),Text(title,style:const TextStyle(fontWeight:FontWeight.w900)),Text(sub,style:TextStyle(color:Colors.white.withOpacity(.6)))])))) ;}
class ActionWide extends StatelessWidget{const ActionWide({super.key,required this.icon,required this.title,required this.sub,this.onTap});final IconData icon;final String title,sub;final VoidCallback? onTap;@override Widget build(BuildContext context)=>InkWell(onTap:onTap,borderRadius:BorderRadius.circular(22),child:Opacity(opacity:onTap == null ? .45 : 1,child:Container(padding:const EdgeInsets.all(16),decoration:BoxDecoration(gradient:LinearGradient(colors:[const Color(0xFF6C63FF).withOpacity(.55),const Color(0xFF00E5FF).withOpacity(.18)]),borderRadius:BorderRadius.circular(22),border:Border.all(color:Colors.white.withOpacity(.1))),child:Row(children:[Icon(icon,size:34),const SizedBox(width:12),Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Text(title,style:const TextStyle(fontWeight:FontWeight.w900)),Text(sub,style:TextStyle(color:Colors.white.withOpacity(.68)))])),const Icon(Icons.arrow_forward_ios_rounded,size:16)])))) ;}

class ChatPage extends StatefulWidget{const ChatPage({super.key,required this.chatId});final String chatId;@override State<ChatPage> createState()=>_ChatPageState();}
class _ChatPageState extends State<ChatPage>{final c=TextEditingController();final scroll=ScrollController();final chat=ChatService();final picker=ImagePicker();bool media=false;bool sending=false;final recorder=AudioRecorder();bool recording=false;@override void dispose(){c.dispose();scroll.dispose();recorder.dispose();super.dispose();}void jump(){Future.delayed(const Duration(milliseconds:200),(){if(scroll.hasClients)scroll.animateTo(scroll.position.maxScrollExtent,duration:const Duration(milliseconds:250),curve:Curves.easeOut);});}Future<void> send()async{if(sending)return;final text=c.text;c.clear();setState(()=>sending=true);try{await chat.sendText(widget.chatId,text);jump();}catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));}finally{if(mounted)setState(()=>sending=false);}}Future<void> sendImage()async{final f=await picker.pickImage(source:ImageSource.gallery,imageQuality:88);if(f!=null)await chat.sendMedia(widget.chatId,'image',f);}Future<void> sendVideo()async{final f=await picker.pickVideo(source:ImageSource.gallery);if(f!=null)await chat.sendMedia(widget.chatId,'video',f);}Future<void> voice()async{if(recording){final path=await recorder.stop();setState(()=>recording=false);if(path!=null)await chat.sendAudioPath(widget.chatId,path);}else{if(!await recorder.hasPermission())return;final dir=await getTemporaryDirectory();final path='${dir.path}/voice_${DateTime.now().millisecondsSinceEpoch}.m4a';await recorder.start(const RecordConfig(encoder:AudioEncoder.aacLc),path:path);setState(()=>recording=true);}}@override Widget build(BuildContext context)=>Scaffold(body:GradientShell(child:SafeArea(child:Column(children:[FutureBuilder<Map<String,dynamic>?>(future:chat.otherProfile(widget.chatId),builder:(context,s)=>ChatHeader(name:s.data?['name']?.toString()??'Duo privado',onAudio:()=>Navigator.push(context,MaterialPageRoute(builder:(_)=>CallPage(chatId:widget.chatId,video:false))),onVideo:()=>Navigator.push(context,MaterialPageRoute(builder:(_)=>CallPage(chatId:widget.chatId,video:true))))),Expanded(child:StreamBuilder<List<Map<String,dynamic>>>(stream:chat.messages(widget.chatId),builder:(context,s){final msgs=s.data??[];if(msgs.isEmpty)return const Center(child:Text('Comece a conversa segura 🔐'));jump();return ListView.builder(controller:scroll,padding:const EdgeInsets.symmetric(vertical:10),itemCount:msgs.length,itemBuilder:(_,i)=>Bubble(chatId:widget.chatId,msg:msgs[i],chat:chat));})),AnimatedSwitcher(duration:const Duration(milliseconds:200),child:media?Container(key:const ValueKey('m'),margin:const EdgeInsets.fromLTRB(12,0,12,8),padding:const EdgeInsets.all(10),decoration:BoxDecoration(color:Colors.white.withOpacity(.08),borderRadius:BorderRadius.circular(22)),child:Row(children:[Expanded(child:FilledButton.tonalIcon(onPressed:sendImage,icon:const Icon(Icons.image_rounded),label:const Text('Foto'))),const SizedBox(width:10),Expanded(child:FilledButton.tonalIcon(onPressed:sendVideo,icon:const Icon(Icons.movie_rounded),label:const Text('Vídeo')))])):const SizedBox.shrink()),Container(padding:const EdgeInsets.all(10),color:Colors.black.withOpacity(.22),child:Row(children:[IconButton.filledTonal(onPressed:()=>setState(()=>media=!media),icon:Icon(media?Icons.close_rounded:Icons.add_rounded)),const SizedBox(width:8),Expanded(child:TextField(controller:c,minLines:1,maxLines:4,decoration:input('Mensagem criptografada...',Icons.lock_rounded),onSubmitted:(_)=>send())),const SizedBox(width:8),IconButton.filledTonal(onPressed:voice,icon:Icon(recording?Icons.stop_rounded:Icons.mic_rounded,color:recording?Colors.redAccent:null)),const SizedBox(width:8),IconButton.filled(onPressed:sending?null:send,icon:sending?const SizedBox(width:16,height:16,child:CircularProgressIndicator(strokeWidth:2)):const Icon(Icons.send_rounded))]))]))));}

class ChatHeader extends StatelessWidget{const ChatHeader({super.key,required this.name,required this.onAudio,required this.onVideo});final String name;final VoidCallback onAudio,onVideo;@override Widget build(BuildContext context)=>Container(padding:const EdgeInsets.fromLTRB(4,6,8,10),decoration:BoxDecoration(color:Colors.black.withOpacity(.18),border:Border(bottom:BorderSide(color:Colors.white.withOpacity(.08)))),child:Row(children:[IconButton(onPressed:()=>Navigator.pop(context),icon:const Icon(Icons.arrow_back_rounded)),CircleAvatar(backgroundColor:const Color(0xFF6C63FF),child:Text(name.characters.first.toUpperCase())),const SizedBox(width:12),Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Text(name,style:const TextStyle(fontWeight:FontWeight.w900)),Text('criptografia ponta a ponta',style:TextStyle(fontSize:12,color:Colors.white.withOpacity(.65)))])),IconButton.filledTonal(onPressed:onAudio,icon:const Icon(Icons.call_rounded)),const SizedBox(width:8),IconButton.filled(onPressed:onVideo,icon:const Icon(Icons.videocam_rounded))]));}

class Bubble extends StatefulWidget{const Bubble({super.key,required this.chatId,required this.msg,required this.chat});final String chatId;final Map<String,dynamic> msg;final ChatService chat;@override State<Bubble> createState()=>_BubbleState();}
class _BubbleState extends State<Bubble>{Uint8List? image;AudioPlayer? player;bool loading=false;bool get mine=>widget.msg['sender_id']==uid;@override void dispose(){player?.dispose();super.dispose();}Future<void> openMedia()async{setState(()=>loading=true);try{final bytes=await widget.chat.downloadMedia(widget.chatId,widget.msg);final type=widget.msg['type'];if(type=='image'){setState(()=>image=bytes);}else{final dir=await getTemporaryDirectory();final file=File('${dir.path}/${widget.msg['file_name']??'media.bin'}');await file.writeAsBytes(bytes);if(type=='audio'){player??=AudioPlayer();await player!.setFilePath(file.path);await player!.play();}else{if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('Vídeo descriptografado em: ${file.path}')));}}}catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('Erro: $e')));}finally{if(mounted)setState(()=>loading=false);}}@override Widget build(BuildContext context){final type=widget.msg['type']??'text';final dt=DateTime.tryParse(widget.msg['created_at']?.toString()??'');final time=dt==null?'':DateFormat('HH:mm').format(dt.toLocal());return Align(alignment:mine?Alignment.centerRight:Alignment.centerLeft,child:Container(constraints:BoxConstraints(maxWidth:MediaQuery.sizeOf(context).width*.78),margin:const EdgeInsets.symmetric(horizontal:14,vertical:6),padding:const EdgeInsets.all(12),decoration:BoxDecoration(gradient:mine?const LinearGradient(colors:[Color(0xFF6C63FF),Color(0xFF5148D9)]):null,color:mine?null:Colors.white.withOpacity(.09),borderRadius:BorderRadius.only(topLeft:const Radius.circular(22),topRight:const Radius.circular(22),bottomLeft:Radius.circular(mine?22:6),bottomRight:Radius.circular(mine?6:22))),child:Column(crossAxisAlignment:CrossAxisAlignment.end,mainAxisSize:MainAxisSize.min,children:[if(type=='text')FutureBuilder<String>(future:widget.chat.decryptTextSafe(widget.chatId,widget.msg),builder:(_,s)=>Text(s.data??'...',style:const TextStyle(fontSize:15.5)))else if(image!=null)ClipRRect(borderRadius:BorderRadius.circular(16),child:Image.memory(image!,fit:BoxFit.cover))else Column(crossAxisAlignment:CrossAxisAlignment.start,children:[Row(mainAxisSize:MainAxisSize.min,children:[Icon(type=='audio'?Icons.graphic_eq_rounded:type=='video'?Icons.movie_rounded:Icons.image_rounded),const SizedBox(width:8),Flexible(child:Text(widget.msg['file_name']?.toString()??'mídia protegida',overflow:TextOverflow.ellipsis))]),const SizedBox(height:8),FilledButton.tonalIcon(onPressed:loading?null:openMedia,icon:loading?const SizedBox(width:16,height:16,child:CircularProgressIndicator(strokeWidth:2)):Icon(type=='audio'?Icons.play_arrow_rounded:Icons.lock_open_rounded),label:Text(type=='audio'?'Tocar':'Abrir'))]),const SizedBox(height:4),Row(mainAxisSize:MainAxisSize.min,children:[const Icon(Icons.lock_rounded,size:12),const SizedBox(width:4),Text(time,style:TextStyle(fontSize:11,color:Colors.white.withOpacity(.7)))])])));}}

class CallPage extends StatefulWidget{const CallPage({super.key,required this.chatId,required this.video});final String chatId;final bool video;@override State<CallPage> createState()=>_CallPageState();}
class _CallPageState extends State<CallPage>{final chat=ChatService();final local=RTCVideoRenderer();final remote=RTCVideoRenderer();RTCPeerConnection? pc;MediaStream? stream;String status='Iniciando chamada...';bool loading=true,mic=true,cam=true;@override void initState(){super.initState();start();}Future<void> start()async{try{await local.initialize();await remote.initialize();final other=await chat.otherProfile(widget.chatId);pc=await createPeerConnection({'iceServers':[{'urls':'stun:stun.l.google.com:19302'},{'urls':'stun:stun1.l.google.com:19302'}],'sdpSemantics':'unified-plan'});stream=await navigator.mediaDevices.getUserMedia({'audio':true,'video':widget.video});local.srcObject=stream;for(final t in stream!.getTracks()){await pc!.addTrack(t,stream!);}pc!.onTrack=(e){if(e.streams.isNotEmpty)remote.srcObject=e.streams.first;};final offer=await pc!.createOffer();await pc!.setLocalDescription(offer);final call=await sb.from('calls').insert({'chat_id':widget.chatId,'caller_id':uid,'receiver_id':other?['id'],'type':widget.video?'video':'audio','status':'ringing','offer':{'type':offer.type,'sdp':offer.sdp}}).select().single();final callId=call['id'];pc!.onIceCandidate=(cand){if(cand.candidate!=null){sb.from('call_candidates').insert({'call_id':callId,'user_id':uid,'candidate':{'candidate':cand.candidate,'sdpMid':cand.sdpMid,'sdpMLineIndex':cand.sdpMLineIndex}});}};setState(() { status='Chamando... sinalização salva no Supabase'; loading=false; });}catch(e){setState(() { status='Erro: $e'; loading=false; });}}Future<void> end()async{for(final t in stream?.getTracks()??[]){await t.stop();}await pc?.close();if(mounted)Navigator.pop(context);}@override void dispose(){local.dispose();remote.dispose();super.dispose();}@override Widget build(BuildContext context)=>Scaffold(body:GradientShell(child:SafeArea(child:Padding(padding:const EdgeInsets.all(16),child:Column(children:[Row(children:[IconButton(onPressed:end,icon:const Icon(Icons.arrow_back_rounded)),Expanded(child:Text(widget.video?'Chamada de vídeo':'Chamada de áudio',style:Theme.of(context).textTheme.titleLarge?.copyWith(fontWeight:FontWeight.w900))),const Icon(Icons.lock_rounded)]),const SizedBox(height:14),Expanded(child:ClipRRect(borderRadius:BorderRadius.circular(32),child:Container(color:Colors.black.withOpacity(.35),child:Stack(children:[Positioned.fill(child:widget.video?RTCVideoView(remote,objectFit:RTCVideoViewObjectFit.RTCVideoViewObjectFitCover):const Center(child:Icon(Icons.graphic_eq_rounded,size:120))),Positioned(top:16,left:16,right:16,child:GlassCard(padding:const EdgeInsets.all(14),child:Row(children:[if(loading)const SizedBox(width:16,height:16,child:CircularProgressIndicator(strokeWidth:2))else const Icon(Icons.security_rounded,size:18),const SizedBox(width:10),Expanded(child:Text(status))]))),if(widget.video)Positioned(right:16,bottom:16,width:118,height:168,child:ClipRRect(borderRadius:BorderRadius.circular(22),child:RTCVideoView(local,mirror:true,objectFit:RTCVideoViewObjectFit.RTCVideoViewObjectFitCover)))])))),const SizedBox(height:18),Row(mainAxisAlignment:MainAxisAlignment.center,children:[CallBtn(icon:mic?Icons.mic_rounded:Icons.mic_off_rounded,onTap:(){setState(()=>mic=!mic);for(final t in stream?.getAudioTracks()??[]){t.enabled=mic;}}),const SizedBox(width:16),CallBtn(icon:Icons.call_end_rounded,danger:true,onTap:end),if(widget.video)...[const SizedBox(width:16),CallBtn(icon:cam?Icons.videocam_rounded:Icons.videocam_off_rounded,onTap:(){setState(()=>cam=!cam);for(final t in stream?.getVideoTracks()??[]){t.enabled=cam;}})]]),]))));}
class CallBtn extends StatelessWidget{const CallBtn({super.key,required this.icon,required this.onTap,this.danger=false});final IconData icon;final VoidCallback onTap;final bool danger;@override Widget build(BuildContext context)=>InkWell(onTap:onTap,borderRadius:BorderRadius.circular(999),child:Container(width:64,height:64,decoration:BoxDecoration(shape:BoxShape.circle,color:danger?Colors.redAccent:Colors.white.withOpacity(.12),border:Border.all(color:Colors.white.withOpacity(.12))),child:Icon(icon,size:30)));}
