package ab1.impl.Hribar_Jahrer;

import java.math.BigInteger;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {
	PublicKey pubk;
	PrivateKey prvk;
	BigInteger n;

	@Override
	public void init(int n) {
		// TODO Auto-generated method stub
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
			phi = new BigInteger(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).toString());
		} while (!e.gcd(phi).equals(BigInteger.ONE)
				|| p.subtract(q).abs().shiftRight(n / 2 - 100).equals(BigInteger.ZERO));

		BigInteger d = e.modInverse(phi);

		this.n = p.multiply(q);

		System.out.println("d: " + d.intValue());
		System.out.println("e: " + e.intValue());
		System.out.println("q: " + q.intValue());
		System.out.println("p: " + p.intValue());

		System.out.println("n: " + this.n.intValue());

		/*
		 * p = new BigInteger(n / 2, 8, rnd);
		 * 
		 * 
		 * 
		 * rnd.nextInt();
		 * 
		 * do { q = new BigInteger(n / 2, 8, rnd); } while (p == q);
		 * 
		 * 
		 * 
		 * this.n = p.multiply(q);
		 * 
		 * 
		 * 
		 * 
		 * 
		 * 
		 * 
		 * 
		 * 
		 * BigInteger d = e.modInverse(phi);
		 */
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

		BigInteger tmp;
		byte[] cipher = new byte[data.length];

		for (int i = 0; i < data.length; i++) {
			System.out.println("data: " + data[i]);
			System.out.println("e: " + pubk.getE().intValue());
			System.out.println("n: " + pubk.getN().intValue());
			tmp = new BigInteger(Byte.toString(data[i]));
			tmp = tmp.modPow(pubk.getE(), pubk.getN());
			cipher[i] = tmp.byteValue();
			System.out.println("cipher: " + cipher[i]);
		}

		return cipher;
	}

	@Override
	public byte[] decrypt(byte[] data) {
		// TODO Auto-generated method stub
		BigInteger tmp;
		byte[] cipher = new byte[data.length];

		for (int i = 0; i < data.length; i++) {
			System.out.println("data" + data[i]);
			tmp = new BigInteger(Byte.toString(data[i]));
			tmp = tmp.modPow(prvk.getD(), prvk.getN());
			cipher[i] = tmp.byteValue();
			System.out.println("cipher: " + cipher[i]);
		}
		return null;
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
