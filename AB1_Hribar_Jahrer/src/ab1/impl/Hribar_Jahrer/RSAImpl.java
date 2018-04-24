package ab1.impl.Hribar_Jahrer;


import java.math.BigInteger;
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
		
		
		
		/*
		 * do { p = random_prime(keysize / 2); q = random_prime(keysize / 2); lambda =
		 * bigInt.lcm(p.minus(1), q.minus(1)); } while (bigInt.gcd(e,
		 * lambda).notEquals(1) || p.minus(q).abs().shiftRight(keysize/2-100).isZero());
		 */

		// e
		BigInteger e = new BigInteger("2");
		e = e.pow(16).add(BigInteger.ONE);

		// phi(n)
		BigInteger phi;// = new BigInteger((p.subtract(BigInteger.ONE).
		// multiply(q.subtract(BigInteger.ONE))).toString());
		
		do {
			p = new BigInteger(n / 2, 8, rnd);
			q = new BigInteger(n / 2, 8, rnd);
			// phi = LCM(q.subtract(BigInteger.ONE), p.subtract(BigInteger.ONE));
			BigInteger pmo = p.subtract(BigInteger.ONE); 
			BigInteger qmo = q.subtract(BigInteger.ONE); 
			phi = pmo.multiply(qmo);
			
			//phi = new BigInteger(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).toString());
		} while (!e.gcd(phi).equals(BigInteger.ONE)
				|| p.equals(q) || p.multiply(q).bitLength() != p.bitLength()+p.bitLength());

		System.out.println("p length: " + p.bitLength());
		System.out.println("q length: " + q.bitLength());
		
		//p.subtract(q).abs().shiftRight(n / 2 - 100).equals(BigInteger.ZERO)
		
		BigInteger d = e.modInverse(phi);

		this.n = p.multiply(q);
		
		System.out.println("n length: " + this.n.bitLength());


		
		System.out.println("d: " + d.toString());
		System.out.println("e: " + e.toString());
		System.out.println("q: " + q.toString());
		System.out.println("p: " + p.toString());

		System.out.println("n: " + this.n.toString());

		
		pubk = new PublicKey(this.n, e);
		prvk = new PrivateKey(this.n, d);

	}

	private BigInteger LCM(BigInteger a, BigInteger b) {
		BigInteger c = a.gcd(b);
		return a.multiply(b.divide(c));
	}

	@Override
	public PublicKey getPublicKey() {
		return pubk;
	}

	@Override
	public PrivateKey getPrivateKey() {
		return prvk;
	}

	@Override
	public byte[] encrypt(byte[] data, boolean activateOAEP) {
		System.out.println("data length: " + data.length);
		System.out.println("data" + Arrays.toString(data));
		BigInteger cipher = new BigInteger(data);
		System.out.println("Data in cipher: " + cipher.toString());
		cipher = cipher.modPow(pubk.getE(), pubk.getN()); 

		/*BigInteger tmp;
		byte[] cipher = new byte[data.length];

		for (int i = 0; i < data.length; i++) {
			System.out.println("data: " + data[i]);
			System.out.println("e: " + pubk.getE().toString());
			System.out.println("n: " + pubk.getN().toString());
			tmp = new BigInteger(Byte.toString(data[i]));
			tmp = tmp.modPow(pubk.getE(), pubk.getN());
			cipher[i] = tmp.byteValue();
			System.out.println("cipher: " + cipher[i]);
		}*/
		System.out.println("cypher length: " + cipher.toByteArray().length);
		System.out.println("cypher:" + Arrays.toString(cipher.toByteArray()));
		return cipher.toByteArray();
	}

	@Override
	public byte[] decrypt(byte[] data) {
		/*BigInteger tmp;
		byte[] cipher = new byte[data.length];

		for (int i = 0; i < data.length; i++) {
			System.out.println("data" + data[i]);
			tmp = new BigInteger(Byte.toString(data[i]));
			tmp = tmp.modPow(prvk.getD(), prvk.getN());
			cipher[i] = tmp.byteValue();
			System.out.println("cipher: " + cipher[i]);
		}
		return cipher;*/
		System.out.println();
		System.out.println("dec cipher leng "+data.length);
		System.out.println("decrypt data "+ Arrays.toString(data));
		BigInteger msg = new BigInteger(data); 
		
		msg = msg.modPow(prvk.getD(), prvk.getN()); 
		System.out.println("decrypt msg: " + Arrays.toString(msg.toByteArray()));
		return msg.toByteArray();
	}

	@Override
	public byte[] sign(byte[] message) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		// TODO Auto-generated method stub
		return null;
	}

}
