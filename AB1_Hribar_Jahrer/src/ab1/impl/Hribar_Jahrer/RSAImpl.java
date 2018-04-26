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
		p = new BigInteger(n / 2, 50, rnd);
		do {
			q = new BigInteger(n / 2, 50, rnd);
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

		// active padding: [0] = 2
		// non active padding: [0] = 1

		System.out.println("--------------Entered encypt------------------");
		System.out.println("Input: " + Arrays.toString(data));
		System.out.println("Input len: " + data.length);
		System.out.println("pubk N bit: " + pubk.getN().bitLength());

		// adding first byte for padding

		byte[] dataWithPaddingIndex = new byte[data.length + 1];
		System.arraycopy(data, 0, dataWithPaddingIndex, 1, data.length);

		if (dataWithPaddingIndex.length < 128 && activateOAEP == false) {
			// path for no padding and oneblock data
			System.out.println("path for no padding and oneblock data");

			dataWithPaddingIndex[0] = 1;

			System.out.println("data for chipher: " + Arrays.toString(dataWithPaddingIndex));

			BigInteger cipher = new BigInteger(dataWithPaddingIndex);
			cipher = cipher.modPow(pubk.getE(), pubk.getN());

			System.out.println("cipher: " + Arrays.toString(cipher.toByteArray()));
			return cipher.toByteArray();

		} else if (dataWithPaddingIndex.length < 127 && activateOAEP == true) {
			// path for padding and oneblock data
			System.out.println("path for padding and oneblock data");

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
			System.out.println("output: " + Arrays.toString(output));
			System.out.println("data for chipher: " + Arrays.toString(output));

			BigInteger cipher = new BigInteger(output);
			cipher = cipher.modPow(pubk.getE(), pubk.getN());

			System.out.println("cipher: " + Arrays.toString(cipher.toByteArray()));
			return cipher.toByteArray();

		} else if (dataWithPaddingIndex.length >= 127 && !activateOAEP) {
			// path for > 1 block data and no padding
			System.out.println("path for > 1 block data and no padding");
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
					//System.out.println("Block: " + Arrays.toString(block));
				}
				// put 127byte block in BigInteger and calc cipher text
				BigInteger cipher = new BigInteger(block);
				cipher = cipher.modPow(pubk.getE(), pubk.getN());
				System.out.println("Cipher: " + cipher.toString().length() + " " + cipher.toByteArray().length + " "
						+ cipher.bitLength() + " " + cipher.toString());
				// Store the output
				outputBuffer.add(cipher.toByteArray());
				// return cipher.toByteArray();
			}

			byte[] cipherText = new byte[outputBuffer.size() * 128];

			System.out.println("buffer length: " + outputBuffer.size());
			for (int i = 0; !outputBuffer.isEmpty(); i++) {
				byte[] temp = outputBuffer.poll();
				System.out.println("temp: " + Arrays.toString(temp));
				System.out.println("temp length: " + temp.length);
				System.arraycopy(temp, 0, cipherText, i * 128, temp.length);
			}

			return cipherText;

		} else if (dataWithPaddingIndex.length >= 126 && activateOAEP) {
			// path for >1 block and padding
			System.out.println("path for >1 block and padding");

			Queue<Byte> buffer = new LinkedList<>();
			Queue<byte[]> outputBuffer = new LinkedList<byte[]>();

			// to fix the problem with leading negative numbers
			buffer.add((byte) 01);
			// Put hole data in queue
			for (byte i : data) {
				buffer.add(i);
			}
			// Padding
			buffer.add((byte) 10);
			
			Random r = new Random();
			
			if(buffer.size() % 127 != 0) {
				for (int i = 127 - (buffer.size() % 127); i > 0; i--) {
					buffer.add((byte) r.nextInt(10));
				}
			}

			while (!buffer.isEmpty()) {
				// get first 127 byte from queue
				System.out.println();
				byte[] block = new byte[127];
				for (int i = 0; i < block.length && !buffer.isEmpty(); i++) {
					block[i] = buffer.poll();
					// System.out.println("Block: " + Arrays.toString(block));
				}
				// But 127byte block in BigInteger and calc cipher text
				BigInteger cipher = new BigInteger(block);
				cipher = cipher.modPow(pubk.getE(), pubk.getN());
				System.out.println("Cipher: " + cipher.toString().length() + " " + cipher.toByteArray().length + " "
						+ cipher.bitLength() + " " + cipher.toString());
				// Store the output
				outputBuffer.add(cipher.toByteArray());
			}

			byte[] cipherText = new byte[outputBuffer.size() * 128];

			System.out.println("buffer length: " + outputBuffer.size());
			for (int i = 0; !outputBuffer.isEmpty(); i++) {
				byte[] temp = outputBuffer.poll();

				// remove leading zero from 2 compliment representation
				/*
				 * if (temp[0] == 0) { System.out.println("REMOVE ZERO"); temp =
				 * Arrays.copyOfRange(temp, 1, temp.length); }
				 */
				System.out.println("temp: " + Arrays.toString(temp));
				System.out.println("temp length: " + temp.length);
				System.arraycopy(temp, 0, cipherText, i * 128, temp.length);
			}
			
			return cipherText;

			/*
			 * if (cipherText[0] == 0) { byte[] tmp = new byte[cipherText.length - 1];
			 * System.arraycopy(cipherText, 1, tmp, 0, tmp.length); cipherText = tmp; }
			 */

		}
		return null;

	}

	public byte[] decrypt(byte[] data) {

		Queue<Byte> buffer = new LinkedList<>();
		Queue<byte[]> outputBuffer = new LinkedList<byte[]>();

		System.out.println("---------------Enter Decypt------------");
		System.out.println("DEC Input: " + Arrays.toString(data));
		System.out.println("DEC Input length: " + data.length);

		byte[] messageWithPaddingIndex;
		BigInteger bi = new BigInteger(data);

		messageWithPaddingIndex = bi.modPow(prvk.getD(), prvk.getN()).toByteArray();

		System.out.println("messageWithPaddingIndex: " + Arrays.toString(messageWithPaddingIndex));

		if (messageWithPaddingIndex.length <= 128 && data.length <= 129) {
			if (messageWithPaddingIndex[0] == 1) {
				// path for no padding and oneblock
				System.out.println("path for no padding and oneblock");

				System.out.println("-_-_-_ messagedec " + Arrays.toString(messageWithPaddingIndex));

				byte[] clearMessage = Arrays.copyOf(messageWithPaddingIndex, messageWithPaddingIndex.length);

				clearMessage = Arrays.copyOfRange(messageWithPaddingIndex, 1, messageWithPaddingIndex.length);

				System.out.println("-_-_-_ clearmessage " + Arrays.toString(clearMessage));

				return clearMessage;

			} else if (messageWithPaddingIndex[0] == 2) {
				// path for padding and oneblock
				System.out.println("path for padding and oneblock");

				System.out.println("-_-_-_ messagedec " + Arrays.toString(messageWithPaddingIndex));

				byte[] clearMessage = Arrays.copyOf(messageWithPaddingIndex, messageWithPaddingIndex.length);

				for (int i = messageWithPaddingIndex.length - 1; i > 0; i--) {
					if (messageWithPaddingIndex[i] == (byte) 10) {
						System.out.println("i = " + i);
						clearMessage = Arrays.copyOfRange(messageWithPaddingIndex, 1, i);
						break;
					}

				}

				System.out.println("-_-_-_ clearmessage " + Arrays.toString(clearMessage));

				return clearMessage;

			}
		} else if (data.length >128){
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
				// Store the output
				
				System.out.println("message parts " + Arrays.toString(cipher.toByteArray()));
				outputBuffer.add(cipher.toByteArray());
			}

			byte[] messageText = new byte[outputBuffer.size() * 128];
			System.out.println("DEC output.length: " + messageText.length);
			System.out.println("DEC buffer length: " + outputBuffer.size());
			for (int i = 0; !outputBuffer.isEmpty(); i++) {
				System.out.println("int i: " + i);
				byte[] temp = outputBuffer.poll();

				System.out.println("DEC temp: " + Arrays.toString(temp));
				System.out.println("DEC Temp length: " + temp.length);
				System.arraycopy(temp, 0, messageText, i * 128, 128);
			}

			System.out.println("messageText: " + Arrays.toString(messageText));

			 if (messageText[0] == 1) {
			// path for no padding and >1 block
			System.out.println("path for no padding and >1 block");
			
			//TODO

			return messageText;

			 } else if (messageText[0] == 2) {
			 //path for padding and >1 block
			 System.out.println("path for padding and >1 block");
			 
			 //TODO
			 
			 
			 }
			 return messageText;
		}
		return null;
	}

	private byte[] cutOfPadding(byte[] arr) {
		// searches from last postition for 10 pattern
		for (int i = arr.length - 1; i >= 0; i--) {
			if (arr[i] == (byte) 10) {
				byte[] cut = new byte[i];
				System.arraycopy(arr, 0, cut, 0, cut.length);
				return cut;
			}
		}
		return arr;
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
