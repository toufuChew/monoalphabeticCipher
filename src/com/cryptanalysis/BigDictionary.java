package com.cryptanalysis;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.util.HashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * BigDictionary provide spelling check
 * @author chenqiu
 *
 */
public class BigDictionary {
	private static boolean ready = false;
	public static final String dict = "/Users/chenqiu/Downloads/big.txt";
	public static final String outname = "big.dict";
	private HashSet<String> words;
	private static void outputDict(String dpath, String oname){
		try {
			File outputFile = new File(dpath.substring(0, dpath.lastIndexOf('/') + 1) + oname);
			if (outputFile.exists())
				return;
			outputFile.createNewFile();
			
			BufferedReader br = new BufferedReader(new FileReader(dpath));
			StringBuffer sb = new StringBuffer();
			String line = null;
			while((line = br.readLine()) != null)
				sb.append(line);
			Pattern p = Pattern.compile("[^A-Za-z\\u0020]");
			Matcher m = p.matcher(sb.toString());
			String []dict = m.replaceAll(" ").split(" ");
			br.close();
			sb = new StringBuffer();
			for (int i = 0; i < dict.length; i++){
				if (dict[i].compareTo("") != 0 && dict[i].charAt(0) != ' ')
					sb.append(dict[i].toLowerCase() + " ");
			}
			BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile));
			bw.write(sb.toString());
			bw.flush();
			bw.close();
			BigDictionary.ready = true;
			System.out.println(oname + " created");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public BigDictionary(String dpath, String oname){
		if (!ready)
			BigDictionary.outputDict(dpath, oname);
		this.words = new HashSet<String>();
		try {
//			FileInputStream fin = new FileInputStream(new File(dpath.substring(0, dpath.lastIndexOf('/') + 1) + oname));
//			int ch;
//			String temp = "";
//			while ((ch = fin.read()) != -1){
//				if (ch != ' ')
//					temp += (char)ch;
//				else{
//					if (!temp.equals(""))
//						words.add(temp);
//					temp = "";
//				}
//			}
//			fin.close();
			
			BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(dpath.substring(0, dpath.lastIndexOf('/') + 1) + oname)));
			String line = "";
			String mesg = "";
			while ((line = br.readLine()) != null)
				mesg += line;
			String []wd = mesg.split(" ");
			for (int i = 0; i < wd.length; i++)
				words.add(wd[i]);
			System.out.println(words.size() + " words.");
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}
	public void update(String words){
		try {
			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(BigDictionary.dict.substring(0, BigDictionary.dict.lastIndexOf('/') + 1) + BigDictionary.outname, true)));
			bw.write(words);
			bw.flush();
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	/**
	 * 检查单词是否出现在词典中
	 * @param word
	 * @return
	 */
	public boolean contains(String word){
		return this.words.contains(word);
	}
	public static void main(String []args){
//		System.out.println("abcd".replace('b'+ "", ""));
		long start = System.currentTimeMillis();
		System.out.println(new BigDictionary(BigDictionary.dict, BigDictionary.outname).contains("love"));
		System.out.println((System.currentTimeMillis() - start) /1000. + "s");
		
	}
}
