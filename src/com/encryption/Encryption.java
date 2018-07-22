package com.encryption;

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
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.cryptanalysis.BigDictionary;

public class Encryption {
	static final String defaultMessage = "/Users/chenqiu/Downloads/cybersecurity/passage.txt";
	public static final String defaultCipher = "/Users/chenqiu/Downloads/cybersecurity/encryption.txt";
	public String encodePath;
	public Encryption(String encodePath){
		this.encodePath = encodePath;
		if (!new File(encodePath).exists())
			try {
				new File(encodePath).createNewFile();
			} catch (IOException e) {
				e.printStackTrace();
			}
	}
	private String encodeByAlphabet(){
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(Encryption.defaultMessage)));
			String txt = new String();
			String line = null;
			while((line = br.readLine()) != null)
				txt += line + " ";
			br.close();
			Pattern p = Pattern.compile("[^A-Za-z\\u0020]");
			Matcher m = p.matcher(txt);
			txt = m.replaceAll(" ").toLowerCase(); //lower case
			
			System.out.println(txt);
			
			BigDictionary big = new BigDictionary(BigDictionary.dict, BigDictionary.outname);
			StringBuffer addMesg = new StringBuffer(); String w = "";
			for (int i = 0; i < txt.length(); i++){
				if (txt.charAt(i) != ' ')
					w += txt.charAt(i);
				else{
					if (w.length() > 3 && !big.contains(w))
						addMesg.append(w + " ");
					w = "";
				}
			}
			big.update(addMesg.toString());
			System.out.println("Dictionary has updated, included new words : \n" + addMesg);
			System.out.println(addMesg.length() + " new words. ");
			char []codingTable = createCodingTable();
			StringBuffer codedMesg = new StringBuffer();
			for (int i = 0; i < txt.length(); i++)
				if (txt.charAt(i) != ' ')
					codedMesg.append(codingTable[txt.charAt(i) - 'a']); //a - *, b - **, ...
				else
					codedMesg.append(' ');
			System.out.println("<plain-cipher>");
			String tables = "";
			for (char i = 'a'; i <= 'z'; i++)
				tables += (i + "-" + codingTable[i - 'a'] + " ");
//			System.out.println(tables);
			outputCodingTable(tables);
//			System.out.println(codedMesg);
			this.writeMessage(codedMesg.toString().trim());
			return codedMesg.toString().trim();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * if encodePath file is empty , return encodeByAlphabet()
	 * @return
	 */
	public String encode(boolean newEncrypt){
		File f = new File(this.encodePath);
		if (!newEncrypt && f.length() > 0){
			try {
				BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f)));
				StringBuffer rtString = new StringBuffer();
				String line = null;
				while((line = br.readLine()) != null)
					rtString.append(line);
				br.close();
				return rtString.toString();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return this.encodeByAlphabet(); 
	}
	private char[] createCodingTable(){
		Random random = new Random();
		String keychar = "";
		int keyWordLength = random.nextInt(5) + 5 ; // 5 - 9
		char [][]matrix = new char[(int) Math.ceil(26. / keyWordLength)][keyWordLength];
		for (int i = 0; i < matrix.length; i++)
			for (int j = 0; j < keyWordLength; j++)
				matrix[i][j] = 0;
		while(keyWordLength -- > 0){		
			int key = random.nextInt(26) + 'a';
			while(keychar.contains((char)key + "")) key = random.nextInt(26) + 'a'; 
			keychar += (char)key;
			matrix[0][keyWordLength] = (char)key;
		}
		keyWordLength = matrix[0].length;
		for (char i = 'a', t = 0; i <= 'z'; i++)
			if (!keychar.contains(i + ""))
				matrix[(i - 'a' - t) / keyWordLength + 1][(i - 'a' - t) % keyWordLength] = i;
			else t++;
		
		char []codingTable = new char[26];
		for (int i = 0, t = 0; i < keyWordLength; i++)
			for (int j = 0; j < matrix.length; j++){
				if (matrix[j][i] != 0x0)
					codingTable[t ++] = matrix[j][i];
			}
		return codingTable;
	}
	private void writeMessage(String mesg){
		try {
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.encodePath)));
			bw.write(mesg);
			bw.flush();
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public static void main(String []args){
		new Encryption(Encryption.defaultCipher).encodeByAlphabet();;
	}
	private void outputCodingTable(String out){
		try {
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.encodePath.substring(0, this.encodePath.lastIndexOf('/') + 1) + "encodeTable.txt")));;
			bw.write(out);
			bw.flush();
			bw.close();
		} catch (IOException e) {	
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
