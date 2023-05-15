package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
  "strings"
  "flag"

  "github.com/fatih/color"
)



func main() {
var fileName string
	flag.StringVar(&fileName, "f", "", "File name containing domains")
	flag.Parse()
	if fileName != "" {
		file, err := os.Open(fileName)
		if err != nil {
			log.Fatalf("Error opening file %v: %v", fileName, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			domain := scanner.Text()
			processDomain(domain)
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading from file %v: %v", fileName, err)
		}
	} else {
		args := flag.Args()
		for _, domain := range args {
			processDomain(domain)
		}
	}
}

func checkMXRecords(domain string) (bool, []*net.MX) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return false, mxRecords
	}
	return len(mxRecords) > 0, mxRecords
}

func checkSPFRecords(domain string) (bool, string) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return false, ""
	}
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			return true, txt
		}
	}
	return false, ""
}

func checkDMARCRecords(domain string) (bool, string) {
	txtRecords, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		log.Printf("Error: %v\n", err)
		return false, ""
	}
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=DMARC1") {
			return true, txt
		}
	}
	return false, ""
}

func checkARecords(domain string) (bool,string){
  ips, err := net.LookupHost(domain)
  if err != nil{
    fmt.Printf("Error: %s\n",err)
    return false,""
  }
  for _, ip := range ips {
    return true, ip
  }
  return false,""
}

func checkCNAME(domain string) (bool,string){
  cname, err := net.LookupCNAME(domain) 
  if err != nil{
    fmt.Printf("Error: %s\n",err)
    return false, ""
  }
  return true, cname
}

func processDomain(domain string) {
  red := color.New(color.FgRed).SprintFunc()
	hasMX, mxRecords := checkMXRecords(domain)
	hasSPF, spfRecord := checkSPFRecords(domain)
	hasDMARC, dmarcRecord := checkDMARCRecords(domain)
	hasA, aRecord := checkARecords(domain)
	hasCNAME, cnameRecord := checkCNAME(domain)

    fmt.Printf("%s\nMX:%-5v\nSPF:%-5v\nDMARC:%-5v\nA:%-5v CNAME:%-5v\nMXRecords:%-30v\nSPFRecord:%-60s\nDMARCRecord:%-60s\nARecord:%-15s\nCNAMEValue:%-30s\n",red(domain), hasMX, hasSPF, hasDMARC, hasA, hasCNAME, mxRecords, spfRecord, dmarcRecord, aRecord, cnameRecord)
}
