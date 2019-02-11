/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author sai xu
 */
public class FileNumber implements java.io.Serializable {
    public int n;
    public String fileName;
    public FileNumber(int number, String file){
        n= number;
        fileName= file;
    }
}
