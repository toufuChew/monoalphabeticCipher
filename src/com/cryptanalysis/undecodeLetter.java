package com.cryptanalysis;

public class undecodeLetter {
	private char letter;
	private int indexInWord;
	public undecodeLetter(char letter, int index){
		this.letter = letter;
		this.indexInWord = index;
	}
	public int indexInWord(){
		return indexInWord;
	}
	public int letter(){
		return letter;
	}
}
