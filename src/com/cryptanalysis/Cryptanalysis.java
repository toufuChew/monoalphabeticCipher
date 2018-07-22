package com.cryptanalysis;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Stack;

import com.encryption.Encryption;

public class Cryptanalysis {
	String []ciphertext; 
	static char []encodeTable = new char[26];
	int []singleFrequency;
	char []singleSet;
	HashMap<String, Integer>[] combinedFrequency;
	/**
	 * threshold:<strong> the strictness of filter</strong></br>
	 * set less than 0.8 if cipher is large, <br>
	 * over 0.8 you can get better result if cipher is short
	 */
	static final float threshold = 0.8f; 
	/**
	 * if cipher text's length is over <strong>10,000</strong> , cut it up
	 */
	static final int quickCheck = (int) 10e3;
	public Cryptanalysis(String ciphertextPath){
		singleFrequency = new int[26];
		singleSet = new char[26];
		for (int i = 0; i < 26; i++)
			singleFrequency[i] = 0;
		combinedFrequency = (HashMap<String, Integer>[]) new HashMap<?, ?>[3];
		for (int i = 0; i < this.combinedFrequency.length; i++)
			this.combinedFrequency[i] = new HashMap<String, Integer>();
		ciphertext = new Encryption(ciphertextPath).encode(true).replaceAll("\\s+", " ").split(" ");
		System.out.println(ciphertext.length + " words");
	}
	public void preAnalysis(){
		for (int i = 0; i < ciphertext.length; i++)
			for (int j = 0; j < ciphertext[i].length(); j++)
				singleFrequency[ciphertext[i].charAt(j) - 'a']++;
		boolean tag[] = new boolean[26];
		int n = 0, k = 0;
		while (true){
			for (int j = 0; j < singleFrequency.length; j++)
				if (!tag[j] && singleFrequency[k] < singleFrequency[j])
					k = j;
			tag[k] = true;
			singleSet[n ++] = (char) (k + 'a');
			int i;
			for (i = 0; i < singleFrequency.length; i++)
				if (!tag[i]) k = i;
			if (i >= singleFrequency.length) break;
		}
		//calculate combined alphabet
		for (int i = 0; i < ciphertext.length; i++){
			int len = ciphertext[i].length();
			if (len <= 3){
				Integer val = null;
				if ((val = combinedFrequency[len - 1].get(ciphertext[i])) != null)
					combinedFrequency[len - 1].put(ciphertext[i], val + 1);
				else
					combinedFrequency[len - 1].put(ciphertext[i], 1);
			}
		}
	}
	public String decodeCipher(){
		ArrayList<CipherNode>[] simpleCipherArray = new ArrayList[3];
		preAnalysis(); //calculate words
		for (int i = 0; i < simpleCipherArray.length; i++)
			simpleCipherArray[i] = new ArrayList<CipherNode>();
		double threshold = ciphertext.length * 0.002 > 1 ? ciphertext.length * 0.002 : 1;
		for (int i = 0; i < simpleCipherArray.length; i++){
			for (Map.Entry<String, Integer> entry : combinedFrequency[i].entrySet())
				if (entry.getValue() > threshold)
					simpleCipherArray[i].add(new CipherNode(entry.getKey(), entry.getValue()));
			Collections.sort(simpleCipherArray[i]);
		}
		while (simpleCipherArray[0].size() > 4 || simpleCipherArray[0].get(simpleCipherArray[0].size() - 1).frequnency() <= 1)
			simpleCipherArray[0].remove(simpleCipherArray[0].size() - 1); // ensure remain 4 single letter
		for (int i = 0; i < simpleCipherArray.length; i++)
			for (int j = 0; j < simpleCipherArray[i].size(); j++)
				System.out.println(simpleCipherArray[i].get(j));
		
//		int sl = simpleCipherArray[0].size() > 3 ? 3 : simpleCipherArray[0].size();
		int sl = simpleCipherArray[0].size();
		int []singlecode = new int[sl];
		for (int i = 0; i < sl; i++)  //record stack sign
			singlecode[i] = i;
		while (singlecode[0] < FormalWords.formalSingle.length){

			for (int i = 0; i < singlecode.length; i++)
				encodeTable[simpleCipherArray[0].get(i).cipher().charAt(0) - 'a'] = FormalWords.formalSingle[singlecode[i]].charAt(0);
			//digraphs
//			int dl = simpleCipherArray[1].size() > 5 ? 5 : simpleCipherArray[1].size();
			int dl = simpleCipherArray[1].size();
			int []doublecode = new int[dl];
			for (int i = 0; i < dl; i ++)
				doublecode[i] = 0; //double code[i] <= formalDouble.length - 1
			while(doublecode[0] < FormalWords.formalDouble.length){
				for (int i = 0; i < doublecode.length; i++){
					String c = simpleCipherArray[1].get(i).cipher();
//					if (c.compareTo("vy") == 0){
//						for (int q = 0; q < doublecode.length; q++)
//							if (q == 4 && FormalWords.formalDouble[doublecode[q]].compareTo("we") == 0){
//								System.out.println("---------------------");
//								for (int p = 0; p < doublecode.length; p++)
//									System.out.println(doublecode[p]);
//							}
//					}
					
					if (doublecode[i] < FormalWords.formalDouble.length && !conflict(c, FormalWords.formalDouble[doublecode[i]])){
						encodeTable[c.charAt(0) - 'a'] = FormalWords.formalDouble[doublecode[i]].charAt(0);
						encodeTable[c.charAt(1) - 'a'] = FormalWords.formalDouble[doublecode[i]].charAt(1);
					}
					else{
						if (doublecode[0] >= FormalWords.formalDouble.length)
							break;
						doublecode[i] ++;
						while (doublecode[i] >= FormalWords.formalDouble.length){
							if (i == 0) break;
							doublecode[i] = 0;
							i --;
							int j = 0, k = 0;
							String dstr = simpleCipherArray[1].get(i).cipher(); 
							for (int n = 0; n < dstr.length(); n++){ // recover 0
								for (j = 0; j < simpleCipherArray[0].size(); j++){
									char ch = simpleCipherArray[0].get(j).cipher().charAt(0);
									if (ch == dstr.charAt(n))
										break;
								}
								if (j >= simpleCipherArray[0].size()){
									for (k = 0; k < i; k++){
										int s;
										for (s = 0; s < dstr.length(); s++)
											if (dstr.charAt(n) == simpleCipherArray[1].get(k).cipher().charAt(s))
												break;
										if (s < dstr.length())
											break;
									}
									if (k >= i)
										encodeTable[dstr.charAt(n) - 'a'] = 0;
								}
							}
							doublecode[i] ++;
						}
						i --;
					}
				}
				
				if (doublecode[0] >= FormalWords.formalDouble.length){
					int index = singlecode.length - 1;
					while (++ singlecode[index] >= FormalWords.formalSingle.length && index > 0){
						singlecode[index] = 0;
						index --;
						if (index == 0){
							singlecode[index] ++;
							break;
						}
					}
					for (int i = index + 1; i < singlecode.length; i++)
						for (int k = 0; k < FormalWords.formalSingle.length; k++){
							int j = 0;
							for (; j < i; j++)
								if (singlecode[j] == k)
									break;
							if (j >= i){
								singlecode[i] = k;
								break;
							}
						}
//					resetTable();
				}
				else{
//					int recover[] = new int[encodeTable.length + 1];
					String []letterDecode = new String[26]; //multiple possibilities
					for (int i = 0; i < letterDecode.length; i++)
						letterDecode[i] = "";
					System.out.println(tripleDecode(simpleCipherArray[2], letterDecode));
					System.out.println(Cryptanalysis.threshold * simpleCipherArray[2].size());
					if (tripleDecode(simpleCipherArray[2], letterDecode) >= Cryptanalysis.threshold * simpleCipherArray[2].size()
							&& letterDecodeExtract(letterDecode) && coupleLetterDecode(letterDecode)){   
						
//						showEncodeTable();
						/*
						System.out.println("singlecode");
						for (int i = 0; i < singlecode.length; i++)
							System.out.println(singlecode[i]);
						System.out.println("doublecode");
						for (int i = 0; i < doublecode.length; i++)
							System.out.println(doublecode[i]);
							*/
						return enumerate(letterDecode);
					}
					else{
						doublecode[doublecode.length - 1] ++; // decode failed, search next match
//						for (int i = 0; i < doublecode.length; i++)
//							System.out.println(doublecode[i]);
					}
				}
//				System.out.println("---------------------");
//				for (int i = 0; i < doublecode.length; i++)
//					System.out.println(doublecode[i]);
			}
		}
		return null;
	}
	public String enumerate(String []letterDecode){
		System.out.println("last step: enumerate words.");
		String[] tempSet = new String[letterDecode.length];
		for (int i = 0; i < tempSet.length; i++)
			if (letterDecode[i].length() > 1)
				tempSet[i] = letterDecode[i];
			else tempSet[i] = "";
		System.out.println("Start Up the Dictionary now, waiting ...");
		BigDictionary dictionary = new BigDictionary(BigDictionary.dict, BigDictionary.outname);
		System.out.println("Down.");
		//add
		String alp = FormalWords.alphabet;
		for (int i = 0; i < encodeTable.length; i++)
			if (encodeTable[i] != 0)
				alp = alp.replace(encodeTable[i] + "", "");
		for (int i = 0; i < tempSet.length; i++){
			if (tempSet[i].length() <= 1)
				continue;
			int count = 0;
			for (int j = 0; j < tempSet.length; j++)
				if (tempSet[j].length() > 1 && tempSet[i].compareTo(tempSet[j]) == 0)
					count ++;
			if (count == tempSet[i].length())
				for (int k = 0; k < tempSet[i].length(); k++)
					alp = alp.replace(tempSet[i].charAt(k) + "", "");
		}
		for (int i = 0; i < tempSet.length; i++)
			if (tempSet[i].length() == 0 && encodeTable[i] == 0)
				tempSet[i] += alp;
		//
//		System.out.println(alp);
		//
		StringBuffer buffcipher = new StringBuffer();
		String []lastDecode = new String[26];
		for (int i = 0; i < lastDecode.length; i++)
			lastDecode[i] = "";
		String outputString = new String();
		for (int i = 0; i < ciphertext.length; i++){
			if (i > Cryptanalysis.quickCheck) break;
			
			ArrayList<undecodeLetter> undecode = new ArrayList<undecodeLetter>();
			ArrayList<AmbiguousCoding> amlist = new ArrayList<AmbiguousCoding>();

			StringBuffer mesg = new StringBuffer();
			Stack<Integer> stack = new Stack<Integer>();
			for (int j = 0; j < ciphertext[i].length(); j++)
				if (encodeTable[ciphertext[i].charAt(j) - 'a'] != 0)
					mesg.append(encodeTable[ciphertext[i].charAt(j) - 'a']);
				else{
					mesg.append(" ");
					undecode.add(new undecodeLetter(ciphertext[i].charAt(j), j));
//					System.out.println("mesg: " + ciphertext[i].charAt(j) + ", " + tempSet[ciphertext[i].charAt(j) - 'a']);
					stack.push(tempSet[ciphertext[i].charAt(j) - 'a'].length() - 1);
				}
			int size = stack.size();
			if (size == 0) {
				outputString += (mesg + " ");
				continue;
			}
			boolean ambiguous = false;
			while(true){
				while(stack.peek() < 0){
					stack.pop(); // last -1
					if (stack.isEmpty())
						break;
					int back = stack.pop();
					stack.push(back - 1);
				}
				if (stack.isEmpty()) break;
				for (int j = stack.size(); j < size; j++)
					stack.push(tempSet[undecode.get(j).letter() - 'a'].length() - 1);
				//
				for (int j = 0; j < stack.size(); j++)
					mesg.replace(undecode.get(j).indexInWord(), undecode.get(j).indexInWord() + 1, 
							tempSet[undecode.get(j).letter() - 'a'].charAt(stack.get(j)) + "");
				//print mesg ...
//				System.out.println(mesg);
				if (dictionary.contains(mesg.toString())){
					int j;
					for (j = 0; j < stack.size(); j++){
						char c = tempSet[undecode.get(j).letter() - 'a'].charAt(stack.get(j));
						int k;
						for (k = j + 1; k < stack.size(); k++)
							if (c == tempSet[undecode.get(k).letter() - 'a'].charAt(stack.get(k)) && 
							undecode.get(j).letter() != undecode.get(k).letter()) // not allow the same decode letter
								break;
						if (k < stack.size())
							break; //failed
						encodeTable[undecode.get(j).letter() - 'a'] = tempSet[undecode.get(j).letter() - 'a'].charAt(stack.get(j));
					}
					if (j >= stack.size()){// else next permutation
						amlist.add(new AmbiguousCoding(mesg.toString(), (char)0, (char)0));
						for (int k = 0; k < stack.size(); k++)
							if (!lastDecode[undecode.get(k).letter() - 'a'].contains(tempSet[undecode.get(k).letter() - 'a'].charAt(stack.get(k)) + ""))
								lastDecode[undecode.get(k).letter() - 'a'] += tempSet[undecode.get(k).letter() - 'a'].charAt(stack.get(k));
						if (amlist.size() <= 1)
							outputString += (mesg.toString() + " ");
						else
							ambiguous = true;
//						System.out.println(mesg);
					}
				}
				int top = stack.pop();
				stack.push(top - 1);
			}
			if (!ambiguous){
				for (int k = 0; k < stack.size(); k++) // remove from tempSet
					for (int p = 0; p < tempSet.length; p++)
						if (tempSet[p].contains(encodeTable[undecode.get(k).letter() - 'a'] + ""))
							tempSet[p] = tempSet[p].replace(encodeTable[undecode.get(k).letter() - 'a'] + "", "");
			}
			else
				buffcipher.append(ciphertext[i] + " ");
			System.out.println(amlist);
//			for (int k = 0; k < lastDecode.length; k++)
//				System.out.println((char)(k + 'a') + ", mesg: " + lastDecode[k]);
		}
		
		boolean wellDecode = true;
		for (int i = 0; i < lastDecode.length; i++){
			if (lastDecode[i].length() > 1) {
				for (int j = 0, k; j < lastDecode[i].length(); j++){
					for (k = 0; k < lastDecode.length; k++)
						if (lastDecode[k].length() == 1 && lastDecode[k].charAt(0) == lastDecode[i].charAt(j)){
							lastDecode[i] = lastDecode[i].replace(lastDecode[k], "");
							j--;
							break;
						}
				}
				if (lastDecode[i].length() > 1)
					wellDecode = false;
			}
		}
		if (wellDecode)
			System.out.println("OK, none collision.");
		else{
			System.out.println("Oh, some letter counld not be confirm well. They're : ");
			for (int i = 0; i < lastDecode.length; i++)
				if (lastDecode[i].length() > 1)
					System.out.println(lastDecode[i]);
		}
		showEncodeTable();
		System.out.println(outputString);
		recoverMessage();
		return outputString;
	}

	/**
	 * encode conflict
	 * @param cipher
	 * @param sample
	 * @return
	 */
	private boolean conflict(String cipher, String sample){
//		System.out.println(cipher + ", " + sample);
//		for (int i = 0; i < sample.length(); i++)
//			if (encodeTable[cipher.charAt(i) - 'a'] != 0 && encodeTable[cipher.charAt(i) - 'a'] != sample.charAt(i))
//				return true;
//		return false;
		for (int i = 0; i < sample.length(); i++){
			for (int j = 0; j < encodeTable.length; j++)
				if (encodeTable[j] == sample.charAt(i) && (j + 'a') != cipher.charAt(i))
					return true;
			if (encodeTable[cipher.charAt(i) - 'a'] != 0 && encodeTable[cipher.charAt(i) - 'a'] != sample.charAt(i))
				return true;
		}
		if ((cipher.charAt(0) == cipher.charAt(1) && sample.charAt(0) != sample.charAt(1)) || (cipher.charAt(0) != cipher.charAt(1) && sample.charAt(0) == sample.charAt(1)))
			return true;
		return false;
	}
	/**
	 * find key space in triple-words
	 * @param list
	 * @param letterDecode the key space
	 * @return
	 */
	private int tripleDecode(ArrayList<CipherNode> list, String []letterDecode){
		int count = 0;
//		int rc = 0;

		int wordLength = FormalWords.formalTriple[0].length();
		
		for (int i = 0; i < list.size(); i++){
			boolean inc = false;
			for (int j = 0; j < FormalWords.formalTriple.length; j++){
				int k;
				for (k = 0; k < wordLength && k >= 0; k++){
					char c = encodeTable[list.get(i).cipher().charAt(k) - 'a'];
					if (c != 0 && c != FormalWords.formalTriple[j].charAt(k))
						break;
					if (c == 0)
						for (int t = 0; t < encodeTable.length; t++)
							if (encodeTable[t] == FormalWords.formalTriple[j].charAt(k)){
								k = -0xf;
								break;
							}
				}
				if (k < wordLength) continue;

				for (k = 0; k < wordLength; k++){
					char c = encodeTable[list.get(i).cipher().charAt(k) - 'a'];
					if (c == 0)
						letterDecode[list.get(i).cipher().charAt(k) - 'a'] += FormalWords.formalTriple[j].charAt(k);
				}
				if (!inc){
					count++;
					inc = true;
				}
			}
			inc = false;
		}
		//print []
		System.out.println("letter decode by triple: ");
		for (int i = 0; i < 26; i++)
			if (letterDecode[i] != "")
				System.out.println((char)('a' + i) + ", mesg: " + letterDecode[i]);
		
		return count;
	}
	
	private boolean letterDecodeExtract(String []letterDecode){
		System.out.println("step 2: extract. ");
		//sort e.g.: x -> adds then x ->d as
		for (int i = 0; i < letterDecode.length; i++){
			if (letterDecode[i].length() <= 0)
				continue;
			int ch[] = new int [26];
			for (int j = 0; j < ch.length; j++)
				ch[j] = 0;
			for (int j = 0; j < letterDecode[i].length(); j++)
				ch[letterDecode[i].charAt(j) - 'a'] ++;
			letterDecode[i] = "";
			for (int j = 0; j < ch.length; j++){
				int max = 0;
				for (int k = 0; k < ch.length; k++)
					if (ch[k] > ch[max])
						max = k;
				if (ch[max] > 0){
					ch[max] = 0;
					letterDecode[i] += (char)(max + 'a');
				}
			}
		}
		
		/*e.g :
		 * a -> we
		 * c -> we
		 * d -> we
		 * comes to clash
		 * */
		for (int i = 0; i < letterDecode.length; i++){
			if (letterDecode[i].length() > 0){
				int count = 0;
				for (int j = 0; j < letterDecode.length; j++)
					if (i != j && letterDecode[i].compareTo(letterDecode[j]) == 0)
						count ++;
				if (count > letterDecode[i].length())
					return false;
			}
		}
		//decode 
		for (int i = 0; i < letterDecode.length; i++)
			if (letterDecode[i].length() == 1)
				encodeTable[i] = letterDecode[i].charAt(0);
		return true;
	}
	@Deprecated
	private void resetTable(){
		for (int i = 0; i < encodeTable.length; i++)
			encodeTable[i] = 0;
	}
	private void showEncodeTable(){
		System.out.println("<plain-cipher>");
		for (int i = 0; i < encodeTable.length; i++)
			System.out.println(encodeTable[i] + "-" + (char)('a' + i));
	}
	public String recoverMessage(){
		StringBuffer rm = new StringBuffer();
		for (int i = 0; i < ciphertext.length; i++){
			for (int j = 0; j < ciphertext[i].length(); j++)
				rm.append(encodeTable[ciphertext[i].charAt(j) - 'a']);
			rm.append(" ");
		}
		try{
			File of = new File(Encryption.defaultCipher.substring(0, Encryption.defaultCipher.lastIndexOf('/') + 1) + "recover.txt");
			if (!of.exists())
				of.createNewFile();
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(of)));
			bw.write(rm.toString());
			bw.flush();
			bw.close();
		} catch (IOException e){
			e.printStackTrace();
		}
		return rm.toString();
	}
	/**
	 * double letter exclude j, q, v, w, x, y (Exception : "savvy" and "www")
	 * @param letterDecode
	 * @return
	 */
	private boolean coupleLetterDecode(String []letterDecode){
		System.out.println("step 3: decode couple letter like : oo (look) ...");
		
		outputDecodeError();
		HashSet<Integer> coupleLetterSet = new HashSet<Integer>();
		for (int i = 0; i < ciphertext.length; i++)
			for (int j = 1; j < ciphertext[i].length(); j++){
				if (ciphertext[i].charAt(j) == ciphertext[i].charAt(j - 1)){
//					System.out.println(ciphertext[i]);
					if (encodeTable[ciphertext[i].charAt(j) - 'a'] == 0)
						coupleLetterSet.add(ciphertext[i].charAt(j) - 'a');
					else{
						int k;
						for (k = 0; k < FormalWords.coupleLetter.length; k++)
							if (encodeTable[ciphertext[i].charAt(j) - 'a'] == FormalWords.coupleLetter[k].charAt(0))
								break;
//						if (k >= FormalWords.coupleLetter.length)
//							return false;
					}
				}
			}
		ArrayList<Integer> coupleMesgSet = new ArrayList<Integer>();
		for (int j = 0, k; j < FormalWords.coupleLetter.length; j++){
			for (k = 0; k < encodeTable.length; k++)
				if (encodeTable[k] == FormalWords.coupleLetter[j].charAt(0))
					break;
			if (k >= encodeTable.length)
				coupleMesgSet.add(FormalWords.coupleLetter[j].charAt(0) - 'a');
		}
		for (Integer it : coupleLetterSet){
			for (int j = 0; j < coupleMesgSet.size(); j++)
				letterDecode[it] += (char)(coupleMesgSet.get(j) + 'a');
			if (letterDecode[it].length() == 1)
				encodeTable[it] = letterDecode[it].charAt(0);
//			System.out.println((char)(it + 'a') + ", mesg: " + letterDecode[it]);
		} 
		return true;
		//ok
	}
	public static void main(String []args){
		Cryptanalysis cry = new Cryptanalysis(Encryption.defaultCipher);
		long start = System.currentTimeMillis();
		cry.decodeCipher();
		System.out.println((System.currentTimeMillis() - start) / 1000.f + " s.");
		System.out.println("OK, Decode completed. ");
		cry.outputDecodeError();
	}
	public void outputDecodeError(){
		File f = new File(Encryption.defaultCipher.substring(0, Encryption.defaultCipher.lastIndexOf('/') + 1) + "encodeTable.txt");
		if (!f.exists())
			return;
		String rt = new String();
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
			String line = null;
			String tableStr = "";
			while ((line = br.readLine()) != null)
				tableStr += line;
			br.close();
			for (int i = 0; i < tableStr.length(); i += 3){
				String code = "";
				if ((i + 1) < tableStr.length() && tableStr.charAt(i + 1) == '-'){
					code += tableStr.substring(i, i + 3);
					if (encodeTable[code.charAt(2) - 'a'] != code.charAt(0))
						rt += (code + " ");
				}
				else i -= 2;
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (rt.length() > 0){
			System.out.println("Ohps, some letters are wrong. ");
			System.out.println(rt + ".");
		}
		else
			System.out.println("well done. 0 error.");
	}
}
