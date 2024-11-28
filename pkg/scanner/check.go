package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

type Finding struct {
	FilePath string   `json:"file_path"`
	Lines    []string `json:"findings"`
}
type Scanner struct {
	Workers      int
	Verbose      bool
	Format       string
	resultsChan  chan Finding
	OutputFile   string
	filesScanned int32
	secretsFound int32
}

func New(workers int, verbose bool, format string, outputFile string) *Scanner {
	bufferSize := workers * 2
	return &Scanner{
		Workers:     workers,
		Verbose:     verbose,
		Format:      format,
		OutputFile:  outputFile,
		resultsChan: make(chan Finding, bufferSize),
	}
}
func isConfigFile(path string) bool {
	extensions := strings.ToLower(filepath.Ext(path))
	configExtensions := map[string]bool{
		".conf":       true,
		".cfg":        true,
		".ini":        true,
		".json":       true,
		".yaml":       true,
		".yml":        true,
		".properties": true,
		// ".xml":        true,
		".env": true,
	}
	return configExtensions[extensions]
}

func containsSensitiveInfo(line string) bool {
	keywords := []string{
		"jdbc:",
		"redis",
		"mysql",
		"pgsql",
		"postgresql",
		"oracle",
		"oss.",
		"oss.accessKey",
		"oss.secretKey",
		"secretKey",
		"accessKey",
		"ak",
		"sk",
		"mongondb",
		"password",
		"username",
		"requirepass",
		"mail",
		"token",
		"datasource",
		"accessKeyId",
		"accessKeySecret",
		"mssql",
		"sqlserver",
		"aliyun",
		"oss",
		"kingbase8",
		"kingbase",
		"SQLite",
		"Neo4j",
		"access_key",
		"access_token",
		"admin_pass",
		"admin_user",
		"algolia_admin_key",
		"algolia_api_key",
		"alias_pass",
		"alicloud_access_key",
		"amazon_secret_access_key",
		"amazonaws",
		"ansible_vault_password",
		"aos_key",
		"api_key",
		"api_key_secret",
		"api_key_sid",
		"api_secret",
		"api.googlemaps AIza",
		"apidocs",
		"apikey",
		"apiSecret",
		"app_debug",
		"app_id",
		"app_key",
		"app_log_level",
		"app_secret",
		"appkey",
		"appkeysecret",
		"application_key",
		"appsecret",
		"appspot",
		"auth_token",
		"auth",
		"authorizationToken",
		"authsecret",
		"aws_access",
		"aws_access_key_id",
		"aws_bucket",
		"aws_key",
		"aws_secret",
		"aws_secret_key",
		"aws_token",
		"AWSSecretKey",
		"b2_app_key",
		"bashrc password",
		"bintray_apikey",
		"bintray_gpg_password",
		"bintray_key",
		"bintraykey",
		"bluemix_api_key",
		"bluemix_pass",
		"browserstack_access_key",
		"bucket_password",
		"bucketeer_aws_access_key_id",
		"bucketeer_aws_secret_access_key",
		"built_branch_deploy_key",
		"bx_password",
		"cache_driver",
		"cache_s3_secret_key",
		"cattle_access_key",
		"cattle_secret_key",
		"certificate_password",
		"ci_deploy_password",
		"client_secret",
		"client_zpk_secret_key",
		"clojars_password",
		"cloud_api_key",
		"cloud_watch_aws_access_key",
		"cloudant_password",
		"cloudflare_api_key",
		"cloudflare_auth_key",
		"cloudinary_api_secret",
		"cloudinary_name",
		"codecov_token",
		"config",
		"conn.login",
		"connectionstring",
		"consumer_key",
		"consumer_secret",
		"credentials",
		"cypress_record_key",
		"database_password",
		"database_schema_test",
		"datadog_api_key",
		"datadog_app_key",
		"db_password",
		"db_server",
		"db_username",
		"dbpasswd",
		"dbpassword",
		"dbuser",
		"deploy_password",
		"digitalocean_ssh_key_body",
		"digitalocean_ssh_key_ids",
		"docker_hub_password",
		"docker_key",
		"docker_pass",
		"docker_passwd",
		"docker_password",
		"dockerhub_password",
		"dockerhubpassword",
		"dot-files",
		"dotfiles",
		"droplet_travis_password",
		"dynamoaccesskeyid",
		"dynamosecretaccesskey",
		"elastica_host",
		"elastica_port",
		"elasticsearch_password",
		"encryption_key",
		"encryption_password",
		"env.heroku_api_key",
		"env.sonatype_password",
		"eureka.awssecretkey",
		"eureka.client.serviceUrl.defaultZone",
		"bes_admin_password",
		"bes_iastool_passport",
	}
	line = strings.ToLower(line)
	for _, keyword := range keywords {
		if strings.Contains(line, keyword) {
			return true
		}
	}
	return false
}
func (s *Scanner) collectResults() {
	fileFindings := make(map[string][]string)
	for result := range s.resultsChan {
		fileFindings[result.FilePath] = append(fileFindings[result.FilePath], result.Lines...)
	}

	var findings []Finding
	for filePath, lines := range fileFindings {
		findings = append(findings, Finding{
			FilePath: filePath,
			Lines:    lines,
		})
	}

	var output string
	if s.Format == "json" {
		jsonData, err := json.MarshalIndent(findings, "", "  ")
		if err == nil {
			output = string(jsonData)
		}
	} else {
		var builder strings.Builder
		builder.WriteString("\nScan Results:\n")
		builder.WriteString("===================================\n")
		for filePath, lines := range fileFindings {
			fmt.Fprintf(&builder, "\nSensitive information found in %s:\n", filePath)
			for _, line := range lines {
				fmt.Fprintf(&builder, "  - %s\n", line)
			}
		}
		output = builder.String()
	}

	// Write to file if OutputFile is specified
	if s.OutputFile != "" {
		err := os.WriteFile(s.OutputFile, []byte(output), 0644)
		if err != nil {
			if s.Verbose {
				fmt.Printf("Error writing to output file: %v\n", err)
			}
		} else if s.Verbose {
			fmt.Printf("\nResults written to: %s\n", s.OutputFile)
		}
	}

	// Always print to stdout unless writing to file
	if s.OutputFile == "" {
		fmt.Print(output)
	}
}
func (s *Scanner) scanFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		if s.Verbose {
			fmt.Printf("Can't open file %s: %v\n", path, err)
		}
		return
	}
	defer file.Close()

	var findings []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if containsSensitiveInfo(line) {
			findings = append(findings, line)
			atomic.AddInt32(&s.secretsFound, 1)
		}
	}
	if len(findings) > 0 {
		s.resultsChan <- Finding{
			FilePath: path,
			Lines:    findings,
		}
	}
}
func (s *Scanner) Scan(root string) error {
	if _, err := os.Stat(root); os.IsNotExist(err) {
		return fmt.Errorf("path %s does not exist", root)
	}
	if s.Verbose {
		fmt.Printf("Start checking path: %s\n", root)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Workers)

	done := make(chan bool)
	go func() {
		s.collectResults()
		done <- true
	}()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if s.Verbose {
				fmt.Printf("Path error %s: %v\n", path, err)
			}
			return nil
		}
		if !info.IsDir() && isConfigFile(path) {
			wg.Add(1)
			sem <- struct{}{}
			atomic.AddInt32(&s.filesScanned, 1)
			go func(filePath string) {
				defer wg.Done()
				defer func() { <-sem }()

				if s.Verbose {
					fmt.Printf("Scanning: %s\n", filePath)
				}
				s.scanFile(filePath)
			}(path)
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Walking path error: %v\n", err)
	}
	wg.Wait()
	close(s.resultsChan)
	<-done

	fmt.Printf("\nScan Summary\n")
	fmt.Printf("=================================\n")
	fmt.Printf("Files scanned: %d\n", s.filesScanned)
	fmt.Printf("Secrets found: %d\n", s.secretsFound)
	return err

}
