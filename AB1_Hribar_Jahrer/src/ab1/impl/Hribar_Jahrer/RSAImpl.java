package ab1.impl.Hribar_Jahrer;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {
	PublicKey pubk;
	PrivateKey prvk;
	BigInteger n;

	@Override
	public void init(int n) {
		BigInteger p, q;
		Random rnd = new Random();

		// e
		BigInteger e = new BigInteger("2");
		e = e.pow(16).add(BigInteger.ONE);

		// phi(n)
		BigInteger phi;
		p = new BigInteger(n / 2, 8, rnd);
		do {
			q = new BigInteger(n / 2, 8, rnd);
			BigInteger pmo = p.subtract(BigInteger.ONE);
			BigInteger qmo = q.subtract(BigInteger.ONE);
			phi = pmo.multiply(qmo);
		} while (!e.gcd(phi).equals(BigInteger.ONE) || p.equals(q)
				|| p.multiply(q).bitLength() != p.bitLength() + p.bitLength());

		BigInteger d = e.modInverse(phi);

		this.n = p.multiply(q);

		pubk = new PublicKey(this.n, e);
		prvk = new PrivateKey(this.n, d);

	}

	public PublicKey getPublicKey() {
		return pubk;
	}

	public PrivateKey getPrivateKey() {
		return prvk;
	}

	public byte[] encrypt(byte[] data, boolean activateOAEP) {

		byte[] input = new byte[data.length + 1];
		input[0] = 01;
		for (int i = 0; i < data.length; i++) {
			input[i + 1] = data[i];
		}

		BigInteger cipher = new BigInteger(input);

		// Message is longer than n//////////////////////////
		if (cipher.compareTo(prvk.getN()) >= 0) {
			String output = "";
			BigInteger queueBlock = cipher;
			while (queueBlock.compareTo(pubk.getN()) >= 0) {
				cipher = queueBlock.shiftRight(8);
				System.out.println(cipher.toString());
				queueBlock = queueBlock.shiftRight(1024);
				output += cipher.modPow(pubk.getE(), pubk.getN());
				System.out.println("round");
			}
			cipher = queueBlock;
			output += cipher.modPow(pubk.getE(), pubk.getN());
			System.out.println(output);
			return output.getBytes();
		}
		////////////////////////////////////////////////////

		System.out.println("cipher to: " + cipher.toString());
		cipher = cipher.modPow(pubk.getE(), pubk.getN());
		return cipher.toByteArray();

	}

	public byte[] decrypt(byte[] data) {

		System.out.println();
		BigInteger msg = new BigInteger(data);

		/*
		 * //Message is longer than n////////////////////////// if
		 * (msg.compareTo(prvk.getN()) >= 0) { String output = ""; BigInteger queueBlock
		 * = msg; while (queueBlock.compareTo(prvk.getN()) >= 0) { msg =
		 * queueBlock.shiftLeft(8); System.out.println(msg.toString()); queueBlock =
		 * queueBlock.shiftLeft(1024); output += msg.modPow(prvk.getD(), prvk.getN());
		 * System.out.println("round"); } msg = queueBlock; output +=
		 * msg.modPow(prvk.getD(), prvk.getN()); System.out.println(output); byte[] temp
		 * = output.getBytes(); byte[] ret = new byte[temp.length - 1]; for (int i = 0;
		 * i < ret.length; i++) { ret[i] = temp[i + 1]; }
		 * System.out.println("decrypted: " + Arrays.toString(ret)); return ret; }
		 * ////////////////////////////////////////////////////
		 */
		msg = msg.modPow(prvk.getD(), prvk.getN());
		System.out.println("decrypt msg: " + msg.toString());

		byte[] temp = msg.toByteArray();
		byte[] ret = new byte[temp.length - 1];
		for (int i = 0; i < ret.length; i++) {
			ret[i] = temp[i + 1];
		}
		System.out.println("decrypted: " + Arrays.toString(ret));
		return ret;
	}

	@Override
	public byte[] sign(byte[] message) {
		// TODO Auto-generated method stub

		System.out.println("message: " + Arrays.toString(message));

		return decrypt(hash(message));
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {

		byte[] encSig = encrypt(signature, false);
		byte[] hashMes = hash(message);

		System.out.println("message: " + Arrays.toString(message));
		System.out.println("signature: " + Arrays.toString(signature));
		System.out.println("encSig: " + Arrays.toString(encSig));
		System.out.println("hashmes: " + Arrays.toString(hashMes));

		boolean allTrue = true;

		if (encSig.length == hashMes.length) {
			for (int i = 0; i < encSig.length; i++) {
				if (encSig[i] != message[i]) {
					allTrue = false;
				}
			}

			if (allTrue == true) {
				return true;
			} else {
				return false;
			}
		}

		return false;
	}

	private byte[] hash(byte[] data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		md.update(data);

		return md.digest();
	}

}
