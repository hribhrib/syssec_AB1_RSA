package ab1.impl.Hribar_Jahrer;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Random;

import ab1.RSA;

public class RSAImpl implements RSA {
	PublicKey pubk;
	PrivateKey prvk;

	@Override
	public void init(int n) {
		BigInteger p, q;
		BigInteger nKey;
		Random rnd = new Random();

		// e
		BigInteger e = new BigInteger("2");
		e = e.pow(16).add(BigInteger.ONE);

		// phi(n)
		BigInteger phi;
		p = new BigInteger(n / 2, 50, rnd);
		do {
			q = new BigInteger(n / 2, 50, rnd);
			BigInteger pmo = p.subtract(BigInteger.ONE);
			BigInteger qmo = q.subtract(BigInteger.ONE);
			phi = pmo.multiply(qmo);
		} while (!e.gcd(phi).equals(BigInteger.ONE) || p.equals(q)
				|| p.multiply(q).bitLength() != p.bitLength() + p.bitLength());

		BigInteger d = e.modInverse(phi);

		nKey = p.multiply(q);

		// initiate keys
		pubk = new PublicKey(nKey, e);
		prvk = new PrivateKey(nKey, d);

	}

	public PublicKey getPublicKey() {
		return pubk;
	}

	public PrivateKey getPrivateKey() {
		return prvk;
	}

	public byte[] encrypt(byte[] data, boolean activateOAEP) {

		// active padding: [0] = 2
		// non active padding: [0] = 1

		// adding first byte for padding

		byte[] dataWithPaddingIndex = new byte[data.length + 1];
		System.arraycopy(data, 0, dataWithPaddingIndex, 1, data.length);

		if (dataWithPaddingIndex.length < 128 && activateOAEP == false) {
			// path for no padding and oneblock data
			dataWithPaddingIndex[0] = 1;

			BigInteger cipher = new BigInteger(dataWithPaddingIndex);
			cipher = cipher.modPow(pubk.getE(), pubk.getN());

			return cipher.toByteArray();

		} else if (dataWithPaddingIndex.length < 127 && activateOAEP == true) {
			// path for padding and oneblock data
			dataWithPaddingIndex[0] = 2;

			Random r = new Random();

			byte[] output = new byte[127];
			for (int i = 0; i < dataWithPaddingIndex.length; i++) {
				output[i] = dataWithPaddingIndex[i];
				if (i == dataWithPaddingIndex.length - 1) {
					output[i + 1] = (byte) 10;
				}
			}

			for (int i = output.length - 1; i > 0; i--) {
				if (output[i] == (byte) 10) {
					break;
				}
				output[i] = (byte) r.nextInt(10);
			}

			BigInteger cipher = new BigInteger(output);
			cipher = cipher.modPow(pubk.getE(), pubk.getN());

			return cipher.toByteArray();

		} else if (dataWithPaddingIndex.length >= 127 && !activateOAEP) {
			// path for > 1 block data and no padding
			Queue<Byte> buffer = new LinkedList<>();
			Queue<byte[]> outputBuffer = new LinkedList<byte[]>();

			// padding = false
			buffer.add((byte) 1);

			// Put hole data in queue
			for (byte i : data) {
				buffer.add(i);
			}

			while (!buffer.isEmpty()) {
				// get first 127 byte from queue
				byte[] block = null;
				if (buffer.size() <= 127) {
					block = new byte[buffer.size()];
				} else {
					block = new byte[127];
				}
				for (int i = 0; i < block.length && !buffer.isEmpty(); i++) {
					block[i] = buffer.poll();
					// System.out.println("Block: " + Arrays.toString(block));
				}
				// put 127byte block in BigInteger and calc cipher text
				BigInteger cipher = new BigInteger(block);
				cipher = cipher.modPow(pubk.getE(), pubk.getN());

				// Store the output
				outputBuffer.add(cipher.toByteArray());
				// return cipher.toByteArray();
			}

			byte[] cipherText = new byte[outputBuffer.size() * 128];

			for (int i = 0; !outputBuffer.isEmpty(); i++) {
				byte[] temp = outputBuffer.poll();
				System.arraycopy(temp, 0, cipherText, i * 128, temp.length);
			}

			return cipherText;

		} else if (dataWithPaddingIndex.length >= 126 && activateOAEP) {
			// path for >1 block and padding
			Queue<Byte> buffer = new LinkedList<>();
			Queue<byte[]> outputBuffer = new LinkedList<byte[]>();

			// to fix the problem with leading negative numbers
			buffer.add((byte) 2);
			// Put hole data in queue
			for (byte i : data) {
				buffer.add(i);
			}
			// Padding
			buffer.add((byte) 10);

			Random r = new Random();

			if (buffer.size() % 127 != 0) {
				for (int i = 127 - (buffer.size() % 127); i > 0; i--) {
					buffer.add((byte) r.nextInt(10));
				}
			}

			while (!buffer.isEmpty()) {
				// get first 127 byte from queue
				byte[] block = new byte[127];
				for (int i = 0; i < block.length && !buffer.isEmpty(); i++) {
					block[i] = buffer.poll();
					// System.out.println("Block: " + Arrays.toString(block));
				}
				// But 127byte block in BigInteger and calc cipher text
				BigInteger cipher = new BigInteger(block);
				cipher = cipher.modPow(pubk.getE(), pubk.getN());
				// Store the output
				outputBuffer.add(cipher.toByteArray());
			}

			byte[] cipherText = new byte[outputBuffer.size() * 128];

			for (int i = 0; !outputBuffer.isEmpty(); i++) {
				byte[] temp = outputBuffer.poll();

				System.arraycopy(temp, 0, cipherText, i * 128, temp.length);
			}

			return cipherText;

		}
		return null;

	}

	public byte[] decrypt(byte[] data) {

		Queue<Byte> buffer = new LinkedList<>();
		Queue<byte[]> outputBuffer = new LinkedList<byte[]>();

		byte[] messageWithPaddingIndex;
		BigInteger bi = new BigInteger(data);

		messageWithPaddingIndex = bi.modPow(prvk.getD(), prvk.getN()).toByteArray();

		if (messageWithPaddingIndex.length <= 128 && data.length <= 129) {
			if (messageWithPaddingIndex[0] == 1) {
				// path for no padding and oneblock
				byte[] clearMessage = Arrays.copyOf(messageWithPaddingIndex, messageWithPaddingIndex.length);

				clearMessage = Arrays.copyOfRange(messageWithPaddingIndex, 1, messageWithPaddingIndex.length);

				return clearMessage;

			} else if (messageWithPaddingIndex[0] == 2) {
				// path for padding and oneblock

				byte[] clearMessage = Arrays.copyOf(messageWithPaddingIndex, messageWithPaddingIndex.length);

				for (int i = messageWithPaddingIndex.length - 1; i > 0; i--) {
					if (messageWithPaddingIndex[i] == (byte) 10) {
						clearMessage = Arrays.copyOfRange(messageWithPaddingIndex, 1, i);
						break;
					}

				}
				return clearMessage;
			}
		} else if (data.length > 128) {
			// Put hole data in queue
			for (int i = 1; i < data.length; i++) {
				buffer.add(data[i]);
			}

			// decrypt data
			while (!buffer.isEmpty()) {
				// get first 128 byte from queue
				byte[] block = new byte[128];

				for (int i = 0; i < block.length && !buffer.isEmpty(); i++) {
					block[i] = buffer.poll();
				}

				// But 128 byte block in BigInteger
				BigInteger cipher = new BigInteger(block);
				cipher = cipher.modPow(prvk.getD(), prvk.getN());
				// Store the outputmessageHashed
				outputBuffer.add(cipher.toByteArray());
			}

			byte[] messageText = new byte[outputBuffer.size() * 128];

			for (int i = 0; !outputBuffer.isEmpty(); i++) {
				byte[] temp = outputBuffer.poll();
				System.arraycopy(temp, 0, messageText, i * 128, 128);
			}

			if (messageText[0] == 1) {
				// path for no padding and >1 block
				// TODO
				return messageText;

			} else if (messageText[0] == 2) {
				// path for padding and >1 block
				// TODO

			}
			return messageText;
		}
		return null;
	}

	@Override
	public byte[] sign(byte[] message) {
		byte[] messageHashed;
		messageHashed = hash(message);

		BigInteger bi = new BigInteger(messageHashed);

		bi = bi.modPow(prvk.getD(), prvk.getN());

		byte[] array = bi.toByteArray();
		if (array[0] == 0) {
			byte[] tmp = new byte[array.length - 1];
			System.arraycopy(array, 1, tmp, 0, tmp.length);
			array = tmp;
		}

		return array;
	}

	@Override
	public Boolean verify(byte[] message, byte[] signature) {
		byte[] array = Arrays.copyOf(signature, signature.length);
		if (array[0] < 0) {
			byte[] tmp = new byte[array.length + 1];
			System.arraycopy(array, 0, tmp, 1, array.length);
			array = tmp;
		}
		BigInteger bi = new BigInteger(array);

		byte[] encSig = bi.modPow(pubk.getE(), pubk.getN()).toByteArray();

		byte[] hashMes = hash(message);

		return compareByteArray(encSig, hashMes);

	}

	private byte[] hash(byte[] data) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		md.update(data);

		return md.digest();
	}

	private boolean compareByteArray(byte[] arr1, byte[] arr2) {
		boolean allTrue = true;

		if (arr1.length == arr2.length) {
			for (int i = 0; i < arr1.length; i++) {
				if (arr1[i] != arr2[i]) {
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

}
