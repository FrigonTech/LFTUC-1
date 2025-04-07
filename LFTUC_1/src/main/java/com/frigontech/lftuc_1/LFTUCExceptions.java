package com.frigontech.lftuc_1;

//------------------------------------Pre-defined Exceptions----------------------------------------
public class LFTUCExceptions{
    public static class PayloadParseFailureException extends Exception {
        public PayloadParseFailureException() {
            super("Payload structure not matching!");
        }
    }
}
