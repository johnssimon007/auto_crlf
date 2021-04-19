yellow=`tput setaf 3`
domain=$1
if [ -z "$domain" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi
recon(){
mkdir -p $domain
cd $domain
echo "Enumerating subdomains using  ${yellow}assetfinder...";
~/go/bin/assetfinder --subs-only $domain >>$domain.assetinder.txt;
echo "Probing for  ${yellow}live host";
cat $domain.assetinder.txt |~/go/bin/httprobe -c 50 >>$domain.live.txt;
input="$domain.live.txt";
echo "checking for  ${yellow}CRLF injection";
while IFS= read -r targets
do
 cat ../lists/crlf_payloads.txt|xargs -I % sh -c "curl  -vs --max-time 9 $targets/% 2>&1 |grep -q '< Set-Cookie: ?crlf'&& echo ' $target seems to be vulnerable'>>$domain.crlf_results.txt||echo 'not vulnerable for target $targets'";

done < "$input"

}
recon
