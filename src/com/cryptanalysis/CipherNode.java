package com.cryptanalysis;

public class CipherNode implements Comparable<CipherNode>{
	private String cipher;
	private int frequency;
	public CipherNode(String cipher, int fre){
		this.cipher = cipher;
		this.frequency = fre;
	}
	@Override
	public int compareTo(CipherNode o) {
//		return o.frequnency - this.frequnency;
		return o.frequency > this.frequency ? 1 : (o.frequency == this.frequency ? 0 : -1);
	}
	public String cipher(){
		return cipher;
	}
	public int frequnency(){
		return frequency;
	}
	public String toString(){
		return "cipher : " + cipher + ": " + frequency;
	}
}
