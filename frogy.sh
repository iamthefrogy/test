#!/bin/bash

################################ Housekeeping tasks ################################

echo -e "\e[94mEnter the organisation name (E.g., Carbon Black): \e[0m"
read org

cdir=$(echo $org | tr '[:upper:]' '[:lower:]' | tr " " "_")
cwhois=$(echo $org | tr " " "+")

echo -e "\e[94mEnter the root domain name (eg: frogy.com): \e[0m"
read domain_name
echo -e "\e[92mHold on! some house keeping tasks being done... \e[0m"

output_dir="output/$cdir"
raw_output_dir="$output_dir/raw_output"
raw_http_responses_dir="$raw_output_dir/raw_http_responses"

mkdir -p $output_dir $raw_output_dir $raw_http_responses_dir

################################ Subdomain enumeration ################################

echo -e "\e[92mIdentifying Subdomains \e[0m"

echo -n "Is this program in the CHAOS dataset? (y/n)? "
read answer

if [ "$answer" != "${answer#[Yy]}" ]; then
    curl -s https://chaos-data.projectdiscovery.io/index.json -o index.json
    chaosvar=$(cat index.json | grep -w $cdir | grep "URL" | sed 's/"URL": "//;s/",//' | xargs)
    rm index.json*

    if [ -z "$chaosvar" ]; then
        echo -e "\e[36mSorry! could not find data in CHAOS DB...\e[0m"
        subfinder -d $domain_name --silent -o $raw_output_dir/subfinder.txtls > /dev/null 2>&1
        cat $raw_output_dir/subfinder.txtls | unfurl domains >> all.txtls
    else
        curl -s "$chaosvar" -O
        unzip -qq *.zip
        cat *.txt >> $raw_output_dir/chaos.txtls
        cat $raw_output_dir/chaos.txtls | unfurl domains >> all.txtls
        echo -e "\e[36mChaos count: \e[32m$(cat $raw_output_dir/chaos.txtls | tr '[:upper:]' '[:lower:]' | anew | wc -l)\e[0m"

        find . | grep .txt | sed 's/.txt//g' | cut -d "/" -f2 | grep  '\.' >> subfinder.domains
        subfinder -dL subfinder.domains --silent -recursive -o $raw_output_dir/subfinder.txtls > /dev/null 2>&1
        rm subfinder.domains

        cat $raw_output_dir/subfinder.txtls | unfurl domains >> all.txtls
        rm *.zip
        rm *.txt
    fi
fi

amass enum -passive -d $domain_name -o $raw_output_dir/amass.txtls > /dev/null 2>&1
cat $raw_output_dir/amass.txtls | unfurl domains | anew >> all.txtls
echo -e "\e[36mAmaas count: \e[32m$(cat $raw_output_dir/amass.txtls | tr '[:upper:]' '[:lower:]' | anew | wc -l)\e[0m"

curl -sk "http://web.archive.org/cdx/search/cdx?url=*."$domain_name"&output=txt&fl=original&collapse=urlkey&page=" |

#################### COMMON_CRAWL ENUMERATION ######################

curl -s "https://index.commoncrawl.org/collinfo.json" | jq -r .[].id | head -n 5 | while read index_id; do
    echo "Checking index $index_id for subdomains"
    curl -s "http://index.commoncrawl.org/$index_id?url=*.$domain_name&output=json" | jq -r .url | cut -d '/' -f3 | sort -u | anew >> output/$cdir/common_crawl.txtls
done

cat output/$cdir/common_crawl.txtls | unfurl domains | anew >> all.txtls
echo -e "\e[36mCommon Crawl count: \e[32m$(cat output/$cdir/common_crawl.txtls | tr '[:upper:]' '[:lower:]'| anew | wc -l)\e[0m"

#################### GATHERING ROOT DOMAINS ######################

python3 rootdomain.py | cut -d " " -f7 | tr '[:upper:]' '[:lower:]' | anew | sed '/^$/d' | grep -v " "|grep -v "@" | grep "\." >> rootdomain.txtls

#################### SUBFINDER2 ENUMERATION ######################

subfinder -dL rootdomain.txtls --silent -o output/$cdir/subfinder2.txtls > /dev/null 2>&1
echo -e "\e[36mSubfinder count: \e[32m$(cat output/$cdir/subfinder2.txtls | tr '[:upper:]' '[:lower:]'| anew | grep -v " "|grep -v "@" | grep "\."  | wc -l)\e[0m"
cat output/$cdir/subfinder2.txtls | unfurl domains | anew >> all.txtls

#################### HOUSEKEEPING TASKS #########################

mv rootdomain.txtls output/$cdir/
echo "www.$domain_name" | unfurl domains >> all.txtls
echo "$domain_name" | unfurl domains >> all.txtls
cat all.txtls | tr '[:upper:]' '[:lower:]' | unfurl domains | anew >> $cdir.master
mv $cdir.master output/$cdir/$cdir.master
sed -i 's/<br>/\n/g' output/$cdir/$cdir.master
rm all.txtls

#################### SUBDOMAIN RESOLVER ######################
dnsx -l output/$cdir/$cdir.master -silent -a -aaaa -cname -ns -txt -ptr -mx -soa -axfr -caa -resp -json -o output/$cdir/resolved.json > /dev/null 2>&1
cat output/$cdir/resolved.json | jq . | grep host | cut -d " " -f4 | cut -d '"' -f2 | xargs | tr " " "\n" | anew > live.assets

##CONVERT JSON TO CSV FOR FUTURE##

############################################################################# PERFORMING WEB DISCOVERY  ##################################################################

httpx -fr -nc -silent -l live.assets -p 80,81,82,88,135,143,300,443,554,591,593,832,902,981,993,1010,1024,1311,2077,2079,2082,2083,2086,2087,2095,2096,2222,2480,3000,3128,3306,3333,3389,4243,4443,4567,
