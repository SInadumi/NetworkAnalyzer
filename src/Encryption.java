
import java.security.SecureRandom;
//import java.nio.ByteBuffer;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class Encryption{ 
		private Cipher encrypter;
		private Cipher decrypter;//いれもん
		
		
		//static byte bytes[] = new byte [16];
		
		private static final String KEY="passwordpassword";
		private static final String ALGORITHM="AES"; 		//暗号アルゴリズム:AES
		private static final String MODE="CBC";				//暗号化モード:CBC
		private static final String PADDING="PKCS5Padding";	//パディング方式:
		
		//コンストラクタ 鍵と暗号化時の初期値を渡す
		public Encryption()throws Exception{ 
		   
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");//暗号アルゴリズムLinuxは"NativePRNG"がデフォルト
			byte seed[]=random.generateSeed(16);						//ブロック先頭の初期値IVを設定;
	
			//byte seed[]=ByteBuffer.allocate(16).putInt(11515159).array();
			
			
			System.out.println("IV="+(seed));	//検証用
			System.out.println("key="+new String(KEY));//検証用
			
		    IvParameterSpec IV=new IvParameterSpec(seed);
		    SecretKeySpec key=new SecretKeySpec(KEY.getBytes(),ALGORITHM);//鍵とアルゴリズムのセット
		    encrypter=Cipher.getInstance(ALGORITHM+"/"+MODE+"/"+PADDING);//暗号化準備
		    encrypter.init(Cipher.ENCRYPT_MODE, key,IV);
		    decrypter=Cipher.getInstance(ALGORITHM+"/"+MODE+"/"+PADDING);//復号準備
		    decrypter.init(Cipher.DECRYPT_MODE, key,IV);
		    
		}
		//暗号化
		public String encrypto(String text) throws Exception{
			byte[] crypto=encrypter.doFinal(text.getBytes());//暗号化の実施
			byte[] str_64=Base64.getEncoder().encode(crypto);
			String str=new String(str_64);
			return str;
		}
		//復号
		public String decrypto(String str_64) throws Exception{
			byte[] str=Base64.getDecoder().decode(str_64.getBytes());
			byte[] text=decrypter.doFinal(str);//復号の実施
			return new String(text);
		}
}
