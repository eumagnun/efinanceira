package br.com.segurosunimed.efinanceira.service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.X509Certificate;

import org.apache.commons.lang3.ArrayUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.com.segurosunimed.efinanceira.util.Configuracao;

@Component
public class CriptografiaService implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final String ALGORITMO_CRIPTOGRAFIA_SIMETRICO = "AES/CBC/PKCS7Padding";
	private static final String ALGORITMO_CRIPTOGRAFIA_ASSIMETRICO = "RSA/none/PKCS1Padding";

	public static final String CONTEUDO_EM_BASE64 = "conteudoEmBase64";
	public static final String CHAVE_EM_BASE64 = "chaveEmBase64";

	@Autowired
	public Configuracao configuracao;

	public Map<String, String> criptografarConteudoEchaves(byte[] conteudo) throws Exception {
		
		Map<String, String> saida = new HashMap<>();

		byte[] chave = gerarChaveSimetrica(128).getEncoded();
		byte[] vetorInicializacao = gerarChaveSimetrica(128).getEncoded();
		

		// TODO TESTE
		//byte[] key = "ABCDEFGHIJKLMNOP".getBytes("UTF-8");
		
		//byte[] vetorInicializacao = new byte[16];
		//vetorInicializacao = "QRSTUVWXYZ012345".getBytes("UTF-8");
		
		//byte[] chave = new byte[16];
		//chave = "ABCDEFGHIJKLMNOP".getBytes("UTF-8");        

		processarCriptografiaMain(conteudo, saida, chave, vetorInicializacao);
		//testeProcessarCriptografiaDescriptografiaComLog(conteudo, saida, chave, vetorInicializacao);

		return saida;

	}

	private void processarCriptografiaMain(byte[] conteudo, Map<String, String> saida, byte[] chave,
			byte[] vetorInicializacao) throws Exception, FileNotFoundException, ClassNotFoundException, IOException {

		System.out.println("\n\nFASE 1 - Conteudo antes da criptografia:\n\n " + converterByteParaString(conteudo) + "\n\n");

		
		
		
		byte[] arquivoXmlCriptografado = criptografarArquivoXml(conteudo, "AES", ALGORITMO_CRIPTOGRAFIA_SIMETRICO,
				chave, vetorInicializacao);

		System.out.println("\n\nFase 2 - Conteudo criptografado:\n\n "+ converterByteParaString(arquivoXmlCriptografado) + "\n\n");

		String arquivoXmlCriptografadoConvertidoParabase64 = converterByteParaBase64(arquivoXmlCriptografado);

		System.out.println("\n\nFase 3 - Conteudo criptografado em base64:\n\n "+ arquivoXmlCriptografadoConvertidoParabase64 + "\n\n");

		System.out.println("\n\nFase 4 - Chave e Vetor de inicialização antes criptografia. CHAVE= "+ converterByteParaString(chave) + " - VETOR_INICIALIZACAO= "+ converterByteParaString(vetorInicializacao));

		byte[] chaveCriptogrfada = criptografarChaveSimetrica(chave, vetorInicializacao);

		System.out.println("\n\nFase 5 - Chave concatenada com Vetor de inicialização APOS criptografia = "	+ converterByteParaString(chaveCriptogrfada));

		String chaveCriptogradadaConvertidaParaBase64 = converterByteParaBase64(chaveCriptogrfada);

		System.out.println(	"\n\nFase 6 - Chave criptografado em base64:\n\n " + chaveCriptogradadaConvertidaParaBase64 + "\n\n");

		saida.put(CONTEUDO_EM_BASE64, arquivoXmlCriptografadoConvertidoParabase64);
		
		saida.put(CHAVE_EM_BASE64, chaveCriptogradadaConvertidaParaBase64);

	}

	private SecretKey gerarChaveSimetrica(int tamanhoChave)	throws NoSuchAlgorithmException, UnsupportedEncodingException, NoSuchProviderException {
		KeyGenerator keygenerator = KeyGenerator.getInstance("AES");
		//keygenerator.init(tamanhoChave);
		SecretKey chave = keygenerator.generateKey();
		return chave;
	}

	private byte[] criptografarArquivoXml(byte[] conteudo, String algoritmoRSAouAES, String algoritmoCriptografia,
			byte[] chave, byte[] iv) throws Exception {

		Cipher cipher = Cipher.getInstance(algoritmoCriptografia, new BouncyCastleProvider());

		SecretKeySpec secretKeySpec = new SecretKeySpec(chave, algoritmoRSAouAES);

		 AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
		
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, paramSpec);

		byte[] conteudoEncriptado = cipher.doFinal(conteudo);

		return conteudoEncriptado;
	}

	private byte[] criptografarChaveSimetrica(byte[] chave, byte[] vetorInicializacao) throws Exception {
		

		X509Certificate cerEFinanceira = lerCertificadoEFinanceira();

		byte[] chaverMaisVetor = new byte[32];
		chaverMaisVetor = chave;
		chaverMaisVetor = ArrayUtils.addAll(chave, vetorInicializacao);
		
		System.out.println("chaverMaisVetor="+converterByteParaString(chaverMaisVetor));

		byte[] chaverMaisVetorCripttografada = null;

		final Cipher cipher = Cipher.getInstance(ALGORITMO_CRIPTOGRAFIA_ASSIMETRICO,new BouncyCastleProvider());

		cipher.init(Cipher.ENCRYPT_MODE, cerEFinanceira.getPublicKey());

		chaverMaisVetorCripttografada = cipher.doFinal(chaverMaisVetor);

		return chaverMaisVetorCripttografada;

	}

	public X509Certificate lerCertificadoEFinanceira() throws Exception {

		InputStream inStream = new FileInputStream(configuracao.getDiretorioCertificadoEfinanceira());
		X509Certificate cert =X509Certificate.getInstance(inStream);
		inStream.close();
		return cert;

	}

	private String converterByteParaBase64(byte[] conteudo) {
		return new String (Base64.getEncoder().encodeToString(conteudo).getBytes(),StandardCharsets.UTF_8);
	}

	private byte[] converterBase64ParaByte(String conteudo) {
		return Base64.getDecoder().decode(conteudo);
	}

	private String converterByteParaString(byte[] conteudo) {
		String str = new String(conteudo, StandardCharsets.UTF_8);
		return str;
	}

	/*****************************************************
	 * Metodos para fins de teste de Descriptografia
	 ******************************************************/
	private void testeProcessarCriptografiaDescriptografiaComLog(byte[] conteudo, Map<String, String> saida,
			byte[] chave, byte[] vetorInicializacao)
			throws Exception, FileNotFoundException, ClassNotFoundException, IOException {
		// -----------------------
		System.out.println(
				"\n\nFASE 1 - Conteudo antes da criptografia:\n\n " + converterByteParaString(conteudo) + "\n\n");
		// -----------------------

		byte[] arquivoXmlCriptografado = criptografarArquivoXml(conteudo, "AES", ALGORITMO_CRIPTOGRAFIA_SIMETRICO,
				chave, vetorInicializacao);

		// -----------------------
		System.out.println("\n\nFase 2 - Conteudo criptografado:\n\n "
				+ converterByteParaString(arquivoXmlCriptografado) + "\n\n");
		// -----------------------

		String arquivoXmlCriptografadoConvertidoParabase64 = converterByteParaBase64(arquivoXmlCriptografado);

		// -----------------------
		System.out.println("\n\nFase 3 - Conteudo criptografado em base64:\n\n ");//+ arquivoXmlCriptografadoConvertidoParabase64 + "\n\n");
		// -----------------------

		// -----------------------
		System.out.println("\n\nFase 4 - Chave e Vetor de inicialização antes criptografia. CHAVE= "
				+ converterByteParaString(chave) + " - VETOR_INICIALIZACAO= "
				+ converterByteParaString(vetorInicializacao));
		// -----------------------

		byte[] chaveCriptogrfada = testeCriptografarChaveSimetricaFake(chave, vetorInicializacao);
		// -----------------------
		System.out.println("\n\nFase 5 - Chave concatenada com Vetor de inicialização APOS criptografia = "
				+ converterByteParaString(chaveCriptogrfada));
		// -----------------------

		String chaveCriptogradadaConvertidaParaBase64 = converterByteParaBase64(chaveCriptogrfada);

		// -----------------------
		System.out.println(
				"\n\nFase 6 - Chave criptografado em base64:\n\n " + chaveCriptogradadaConvertidaParaBase64 + "\n\n");
		// -----------------------

		saida.put(CONTEUDO_EM_BASE64, arquivoXmlCriptografadoConvertidoParabase64);
		saida.put(CHAVE_EM_BASE64, chaveCriptogradadaConvertidaParaBase64);

		System.out.println("\n\n========Desfazendo========\n\n");
		// -----------------------
		byte[] arquivoRevertidoBase64 = converterBase64ParaByte(arquivoXmlCriptografadoConvertidoParabase64);
		System.out.println("\n\nDesfazer-Fase 1 - Conteudo convertido de base64 para byte[]:\n\n ");//+ converterByteParaString(arquivoRevertidoBase64) + "\n\n");

		byte[] chaveRevertidaDaBase64 = converterBase64ParaByte(chaveCriptogradadaConvertidaParaBase64);
		//System.out.println("\n\nDesfazer-Fase 2 - Chave convertida de base64 para byte[]:\n\n "	+ converterByteParaString(chaveRevertidaDaBase64) + "\n\n");

		byte[] chaveDecriptografada = decriptografaComChaveRsa(chaveRevertidaDaBase64);
		System.out.println("\n\nDesfazer-Fase 3 - Chave Decriptografada:\n\n "
				+ converterByteParaString(chaveDecriptografada) + "\n\n");

		byte[] chaveRevertida = ArrayUtils.subarray(chaveDecriptografada, 0, 16);
		byte[] vetorInicializacaoRevertida = ArrayUtils.subarray(chaveDecriptografada, 16, 32);
		// -----------------------
		System.out.println("\n\nDesfazer-Fase 4- Chave e Vetor de inicialização DECRIPTOGRAFADOS. CHAVE= "
				+ converterByteParaString(chaveRevertida) + " - VETOR_INICIALIZACAO= "
				+ converterByteParaString(vetorInicializacaoRevertida));
		// -----------------------

		String conteudoDecriptografado = decriptografar(arquivoRevertidoBase64, ALGORITMO_CRIPTOGRAFIA_SIMETRICO,
				chaveRevertida, vetorInicializacaoRevertida);

		// -----------------------
		System.out.println("\n\nDesfazer-Fase 5- Conteudo decriptografado:\n\n " + conteudoDecriptografado + "\n\n");
		// -----------------------
	}

	public PublicKey carregarChavePublicaRsa() throws FileNotFoundException, IOException, ClassNotFoundException {
		ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("D:/efinanceira/keys/public.key"));
		final PublicKey chavePublica = (PublicKey) inputStream.readObject();
		inputStream.close();

		return chavePublica;
	}

	public PrivateKey carregarChavePrivadaRsa() throws FileNotFoundException, IOException, ClassNotFoundException {
		// Decriptografa a Mensagem usando a Chave Pirvada
		ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream("D:/efinanceira/keys/private.key"));
		final PrivateKey chavePrivada = (PrivateKey) inputStream.readObject();
		inputStream.close();
		return chavePrivada;
	}

	private String decriptografar(byte[] conteudoCriptografado, String algoritmoCriptografia, byte[] chave, byte[] iv)
			throws Exception {
		Cipher decripta = Cipher.getInstance(algoritmoCriptografia, new BouncyCastleProvider());
		SecretKeySpec key = new SecretKeySpec(chave, "AES");
		decripta.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		return new String(decripta.doFinal(conteudoCriptografado), "UTF-8");
	}

	public byte[] decriptografaComChaveRsa(byte[] conteudo)
			throws FileNotFoundException, ClassNotFoundException, IOException {
		byte[] dectyptedText = null;
		PrivateKey key = carregarChavePrivadaRsa();
		try {
			final Cipher cipher = Cipher.getInstance("RSA");
			// Decriptografa o texto puro usando a chave Privada
			cipher.init(Cipher.DECRYPT_MODE, key);
			dectyptedText = cipher.doFinal(conteudo);

		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return dectyptedText;
	}

	private byte[] testeCriptografarChaveSimetricaFake(byte[] chave, byte[] vetorInicializacao) throws Exception {
		
		byte[] chaverMaisVetor = ArrayUtils.addAll(chave, vetorInicializacao);

		byte[] chaveEmBinarioConcatenadoComVetorEmBInarioCriptografada = null;

		final Cipher cipher = Cipher.getInstance(ALGORITMO_CRIPTOGRAFIA_ASSIMETRICO, new BouncyCastleProvider());

		cipher.init(Cipher.ENCRYPT_MODE, carregarChavePublicaRsa() );

		chaveEmBinarioConcatenadoComVetorEmBInarioCriptografada = cipher.doFinal(chaverMaisVetor);

		return chaveEmBinarioConcatenadoComVetorEmBInarioCriptografada;

	}
}
