package burp;

import java.io.*;
import java.net.URL;
import java.util.*;

import com.squareup.okhttp.*;
import java.io.PrintWriter;
import java.util.List;

public class BurpExtender implements IBurpExtender,IScannerCheck {
    private List<Ulist> ulists = new ArrayList<Ulist>();

    public IBurpExtenderCallbacks callbacks;

    public IExtensionHelpers helpers;

    public PrintWriter stdout;

    @Override

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        // TODO Auto-generated method stub



        this.callbacks = callbacks;

        stdout = new PrintWriter(callbacks.getStdout(),true);

        this.helpers = callbacks.getHelpers();



        callbacks.setExtensionName("Fastjson RCE check");

        callbacks.registerScannerCheck(this);

        stdout.println("[+] ##############################################");
        stdout.println("[+]    anthor: youqi");
        stdout.println("[+]    github: https://github.com/youki992");
        stdout.println("[+] ##############################################");



    }


    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) throws IOException {
//获取检查的url
        String line;
        String dnslogStr1 = null;
        String dnslogStr;
        String token = null;
        List<IScanIssue> issues = new ArrayList<>();
        stdout.println("接收URL");
        URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
        stdout.println(url);
//防止重复检查
        if (!checUrl(url.getHost(), url.getPort())) {
            return null;
        }
        String reqMethod = helpers.analyzeRequest(baseRequestResponse).getMethod();
        List<String> headers = helpers.analyzeRequest(baseRequestResponse).getHeaders();
        //IHttpService httpService = baseRequestResponse.getHttpService();
        //String ip = httpService.getHost();
        //stdout.println("Host: "+ip);
        for (String header : headers) {
//如果为JSON提交的POST数据，检查是否存在fastjson漏洞
        if ((header.contains("application/json") && reqMethod.equals("POST"))) {
                stdout.println("doPassiveScan");

                while (true) {
                    //String currentDir = System.getProperty("user.dir");
                    //stdout.println("当前目录"+currentDir);
                    BufferedReader dnslog = new BufferedReader(new FileReader("dnslog.txt"));
                    try {
                        dnslogStr1 = dnslog.readLine();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    try {
                        token = dnslog.readLine();
                        break;
                    } catch (IOException e) {
                        e.printStackTrace();
                }
                }


                long time = new Date().getTime();
                dnslogStr = time + "." + dnslogStr1;
                stdout.println("使用dnslog： "+dnslogStr);
                try {
                    BufferedReader poc = new BufferedReader(new FileReader("poc.txt"));
                    while ((line = poc.readLine()) != null) {
                    String Trueline = "{'youqi':"+line+"}";
                    line = Trueline.replaceAll("dnslog",dnslogStr);
                    OkHttpClient okHttpClient = new OkHttpClient();
                    RequestBody requestBody = RequestBody.create(MediaType.parse("application/json"),line);
                    Request.Builder builder = new Request.Builder();
                    Request request = builder.url(url).post(requestBody).build();
                    Response response = okHttpClient.newCall(request).execute();
                    stdout.println("POC已发送，扫描地址："+url);
                    OkHttpClient okHttpClient2 = new OkHttpClient();

                    RequestBody requestBody2 =  RequestBody.create(MediaType.parse("application/x-www-form-urlencoded"),token);
                    Request.Builder builder2 = new Request.Builder();
                    Request request2 = builder2.url("https://dig.pm/get_results").post(requestBody2).build();
                    Response response2 = okHttpClient2.newCall(request2).execute();
                    String echo = response2.body().string();
                    //stdout.println("token:"+token);
                    //stdout.println("已向dnslog请求: "+echo);
                    if(echo.contains(dnslogStr)){
                        stdout.println("Target "+url+" is vul to poc: "+ Trueline);
                    }
                }
                poc.close();
            } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }}return issues;
        }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    /**
     * 同一条URL不重复检测
     * @param host
     * @return
     */
    boolean checUrl(String host, int port){
        for (Ulist u : this.ulists) {
            if (u.host.equals(host) && u.port == port)
                return false;
        }
        return true;
    }


    public class Ulist{
        final String host;
        final int port;

        public Ulist(String host,int port){
            this.host = host;
            this.port = port;
        }
    }
}
