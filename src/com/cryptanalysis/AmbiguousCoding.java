package com.cryptanalysis;

public class AmbiguousCoding {
	private String mesg;
	private char cipherLetter;
	private char decodeLetter;
	public AmbiguousCoding(String mesg, char c, char d){
		this.mesg = mesg;
		this.cipherLetter = c;
		this.decodeLetter = d;
	}
	public char cipherLetter(){
		return cipherLetter;
	}
	public char decodeLetter(){
		return decodeLetter;
	}
	public String word(){
		return mesg;
	}
	public String toString(){
		return mesg;
	}
}
