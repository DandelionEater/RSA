/*
	1 taškas – pradinių duomenų įvedimas: du pirminiai skaičiai p ir q, pradinis tekstas x.				+

	3 taškai – šifravimo/dešifravimo algoritmams reikalingų parametrų radimas. 
		Viešojo rakto radimas, privačiojo rakto radimas,												+
		Euklido algoritmo realizavimas,																	+
		Euklido išplėstinio algoritmo realizavimas.														+										

	1 taškas – pradinio teksto užšifravimas.															+

	1 taškas – užšifruoto teksto ir viešojo rakto išsaugojimas failų sistemoje arba duomenų bazėje.		+

	1 taškas – užšifruoto teksto nuskaitymas iš failų sistemos arba duomenų bazės.						+

	3 taškai – užšifruoto teksto dešifravimas.  
		Dešifravimo metodui reikalingas papildomas metodas,												+
		kuris turėdamas n turi surasti du pirminius skaičius, kurie reikalingi ieškant Φ[n] reikšmės.	+
		Turint Φ[n] ir e apskaičiuojamas privatusis raktas.												?
 */

using ExtensionMethods;
using System.Numerics;

class Program {
	static Scanner scanner = new();

	static void Main() {
		restart:

		int operation = SelectionMenu("Please select the operation", new List<string> { "Encrypt", "Decrypt" });

		switch(operation) {
			case 0: { // Encrypt
				BigInteger p,q;
				string text;

				p = scanner.NextInt("Enter the first prime number: ") ?? 0;
				if (!isPrime(p))
					throw new Exception("The number entered is not a prime number");

				q = scanner.NextInt("Enter the second prime number: ") ?? 0;
				if (!isPrime(q))
					throw new Exception("The number entered is not a prime number");

				text = scanner.NextString("Enter the text to encrypt: ") ?? "";

				RSA rsa = new RSA(p, q);

				List<BigInteger> encryptedText = rsa.Encoder(text);

				Console.WriteLine("Encoded text:\n{0}\n" + encryptedText.Join(' '), rsa.n);

				bool stf = SelectionMenu("Save to file?", new List<string> { "No", "Yes" }) == 1;

				if(stf) {
					File.WriteAllText("data.txt", string.Format("{0}\n{1}", encryptedText.Join(' '), rsa.PublicKey));
				}
				break;
			}

			case 1: {
				int n;
				List<BigInteger> encryptedText = new();

				if (File.Exists("data.txt") && SelectionMenu("Read from file?", new List<string> { "No", "Yes" }) == 1) {
					var lines = new List<string>(File.ReadAllLines("data.txt")[0].Split(' '));

					foreach (var line in lines) {
						if(BigInteger.TryParse(line, out var bigInt))
							encryptedText.Add(bigInt);
					}
				} else {
					Console.Write("Enter the encrypted text: ");
					BigInteger? num = scanner.NextInt();

					while (num.HasValue) {
						encryptedText.Add(num.Value);
						num = scanner.NextInt(true);
					}
				}

				n = scanner.NextInt("Enter n: ") ?? -1;
				if (n == -1)
					throw new IndexOutOfRangeException("The specified n is invalid");

				RSA rsa = new RSA(n);

				var text = rsa.Decoder(encryptedText);

				Console.WriteLine("Decoded text:\n" + text);
				break;
			}
		}

		if (SelectionMenu("Continue working?", new List<string> { "No", "Yes" }) == 1)
			goto restart;
	}

	static bool isPrime(BigInteger n) {
		BigInteger a = 0;
		for (int i = 1; i <= n; i++) {
			if (n % i == 0) {
				a++;
			}
		}

		return a == 2;
	}

	static int SelectionMenu(string prompt, List<string> options) {
		Console.WriteLine(prompt);

		for (int i = 0; i < options.Count; i++) {
			Console.WriteLine("[{0}] {1}", i, options[i]);
		}

		Console.Write("Your selection: ");
		int selection = scanner.NextInt() ?? -1;

		while(selection < 0 || selection >= options.Count) {
			Console.WriteLine("Invalid selection, try again.");
			Console.Write("Your selection: ");
			selection = scanner.NextInt() ?? -1;
		}

		return selection;
	}
}

class RSA {

	#region Values

	public BigInteger prime1 { get; private set; }
	public BigInteger prime2 { get; private set; }

	public BigInteger PublicKey { get; private set; }
	public BigInteger PrivateKey { get; private set; }

	public BigInteger n { get; private set; }
	public BigInteger fi { get; private set; }

	#endregion

	#region Constructors

	public RSA (BigInteger _prime1, BigInteger _prime2) {
		prime1 = _prime1;
		prime2 = _prime2;

		n = prime1 * prime2;
		fi = (prime1 - 1) * (prime2 - 1);

		PublicKey = GeneratePublicKey();
		PrivateKey = GeneratePrivateKey();
	}

	public RSA (BigInteger _n) {
		n = _n;

		prime1 = FindPrimeFactor(n);
		prime2 = n / prime1;

		fi = (prime1 - 1) * (prime2 - 1);

		PublicKey = GeneratePublicKey();
		PrivateKey = GeneratePrivateKey();
	}

	#endregion

	public List<BigInteger> Encoder (string message) {
		List<BigInteger> encoded = new List<BigInteger>();
		foreach (char letter in message) {
			encoded.Add(EncryptChar(letter));
		}
		return encoded;
	}

	public string Decoder (List<BigInteger> encoded) {
		string s = "";
		foreach (BigInteger num in encoded) {
			s += (char)DecryptChar(num);
		}
		return s;
	}

	private BigInteger EncryptChar (int message) {
		BigInteger encrypted_text = 1;
		BigInteger e = PublicKey;
		while (e > 0) {
			encrypted_text *= message;
			encrypted_text %= n;
			e -= 1;
		}
		return encrypted_text;
	}

	private BigInteger DecryptChar (BigInteger encrypted_text) {
		BigInteger decrypted = 1;
		BigInteger d = PrivateKey;
		while (d > 0) {
			decrypted *= encrypted_text;
			decrypted %= n;
			d -= 1;
		}
		return decrypted;
	}

	private BigInteger GeneratePublicKey () {
		BigInteger e = 2;

		while (true) {
			if (GCD(e, fi) == 1) {
				break;
			}
			e += 1;
		}

		return e;
	}

	private BigInteger GeneratePrivateKey () {
		BigInteger d = 2;

		while (true) {
			if ((d * PublicKey) % fi == 1) {
				break;
			}
			d += 1;
		}

		return d;
	}

	private BigInteger FindPrimeFactor (BigInteger n) {
		for (int i = 2; i <= n / i; i++) {
			while (n % i == 0) {
				return i;
			}
		}
		return n;
	}

	private BigInteger GCD (BigInteger a, BigInteger b) { // Euklido algoritmas
		if (b == 0) {
			return a;
		}
		return GCD(b, a % b);
	}

	private BigInteger EED (BigInteger a, BigInteger b) { // Euklido išplėstinis algoritmas
		BigInteger x = 0, y = 1, u = 1, v = 0;
		while (a != 0) {
			BigInteger q = b / a;
			BigInteger r = b % a;
			BigInteger m = x - u * q;
			BigInteger n = y - v * q;
			b = a;
			a = r;
			x = u;
			y = v;
			u = m;
			v = n;
		}
		return y;
	}
}

// Prerequisite classes for console input
class Scanner {
	List<int> IntBuffer = new();
	List<string> StringBuffer = new();

	public int? NextInt(bool stopAtBufferEmpty = false) {
		if (IntBuffer.Count != 0)
			return IntBuffer.Shift();

		if (stopAtBufferEmpty)
			return null;

		ParseInput(Console.ReadLine() ?? "");

		if (IntBuffer.Count == 0)
			return null;

		return IntBuffer.Shift();
	}

	public int? NextInt(string prompt) {
		if (IntBuffer.Count != 0)
			return IntBuffer.Shift();

		Console.Write(prompt);

		return NextInt();
	}

	public string? NextString () {
		if (StringBuffer.Count != 0)
			return StringBuffer.Shift();

		ParseInput(Console.ReadLine() ?? "");

		if (StringBuffer.Count == 0)
			return null;

		return StringBuffer.Shift();
	}

	public string? NextString (string prompt) {
		if (StringBuffer.Count != 0)
			return StringBuffer.Shift();

		Console.Write(prompt);

		return NextString();
	}

	private void ParseInput(string input) {
		List<string> nums = new(input.Split(' '));

		var tempString = "";

		foreach (string s in nums) {
			if(int.TryParse(s, out int num)) {
				IntBuffer.Add(num);
				if(tempString != "")
					StringBuffer.Add(tempString.Trim());
				tempString = "";
			} else {
				tempString += s + " ";
			}
		}

		if (tempString != "")
			StringBuffer.Add(tempString.Trim());
	}
}

namespace ExtensionMethods {
	public static class ListExtensions {
		public static T Shift<T>(this List<T> list) {
			if (list.Count == 0)
				throw new IndexOutOfRangeException("The list is empty");

			T val = list[0];

			list.RemoveAt(0);

			return val;
		}

		public static string Join<T>(this List<T> list, char separator) {
			string s = "";

			foreach (T item in list) {
				s += item.ToString() + ((list.IndexOf(item) < list.Count - 1) ? separator : "");
			}

			return s;
		}
	}
}
