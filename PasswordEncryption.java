import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;

public class PasswordEncryption 
{
	
	public void readWriteFile(String inputFile, String outputFile, String tableName, String columnName) throws Exception
	{
		Writer output = null;
		BufferedReader br = null;
		FileOutputStream file = null;
		FileInputStream fstream = null;
		try 
		{
			file = new FileOutputStream(outputFile);
			output = new BufferedWriter(new OutputStreamWriter(file, "UTF-8"));  
            
            fstream = new FileInputStream(inputFile);            
            br = new BufferedReader(new InputStreamReader(fstream, "UTF-8"));  
            String strLine;  
            int counter = 0;
            //Read File Line By Line  
            while ((strLine = br.readLine()) != null) 
            { 
            	counter++;
            	if(counter==1)continue;
            	if(strLine.equals("NULL")||strLine.endsWith("=")) continue;
            	String	encryptedString = DataCipherer.encrypt(strLine);
            	output.write("update "+tableName+" set "+columnName+"='"+encryptedString+"' where "+columnName+"='"+strLine+"';");
            	output.write("\n");
            }
        } 
		catch (Exception e) 
		{  
            System.err.println("Error: " + e.getMessage()); 
            throw e;
        }
		finally
		{			 
			if(output!=null)output.close(); 
			if(br != null)br.close();
			if(file!=null) file.close();
			if(fstream!=null) fstream.close();
			
		}
	}
	
	public static void main(String[] args) 
	{
		PasswordEncryption obj = new PasswordEncryption();
		try
		{
			// device table 	connection_request_password column
			obj.readWriteFile("/tmp/dec_file_device_conn_password", 
								"/tmp/enc_file_device_conn_password.sql",
								"device_management.device", 
								"connection_request_password");
			
			// device table 	password column
			obj.readWriteFile("/tmp/dec_file_device_password", 
								"/tmp/enc_file_device_password.sql",
								"device_management.device", 
								"password");
			
			// device_parameters_dlms table 	secret column
			obj.readWriteFile("/tmp/dec_file_dlms_secret", 
								"/tmp/enc_file_dlms_secret.sql",
								"device_management.device_parameters_dlms", 
								"secret");
			
			// device_model table 	connection_request_password column
			obj.readWriteFile("/tmp/dec_file_devmod_conn_password", 
								"/tmp/enc_file_devmod_conn_password.sql",
								"device_model_management.device_model", 
								"connection_request_password");
					
			// device_model table 	password column
			obj.readWriteFile("/tmp/dec_file_devmod_password", 
								"/tmp/enc_file_devmod_password.sql",
								"device_model_management.device_model", 
								"password");
		}
		catch(Exception ex)
		{
			System.err.println("Exit JVM with error code 1");
			System.exit(1);
		}
		System.exit(0);
	}
}
