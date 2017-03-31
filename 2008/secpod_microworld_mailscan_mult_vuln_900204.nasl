##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_microworld_mailscan_mult_vuln_900204.nasl 5426 2017-02-26 17:47:00Z cfi $
# Description: MicroWorld MailScan for Mail Servers multiple vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900204");
  script_version("$Revision: 5426 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-26 18:47:00 +0100 (Sun, 26 Feb 2017) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3726");
  script_bugtraq_id(30700);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_category(ACT_MIXED_ATTACK);
  script_family("Web application abuses");
  script_name("MicroWorld MailScan for Mail Servers multiple vulnerabilities");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445, 10443);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/31534");
  script_xref(name : "URL" , value : "http://www.oliverkarow.de/research/mailscan.txt");

  tag_impact = "Successful Remote exploitation will allow, to gain unauthorized
  access to disclose sensitive information, directory traversal attacks,
  cross site scripting, execution fo arbitrary script code within the
  context of the website to steal cookie-based authentication credentials.

  Impact Level : Application";

  tag_solution = "Upgrade to MicroWorld MailScan Version 6.4a or later.
  For updates refer to http://www.mwti.net/";

  tag_affected = "MicroWorld MailScan for Mail Servers 5.6a and prior versions.";

  tag_insight = "Multiple flaws are due to,
        - an input validation error within the web administration interface.
        - the web administration interface does not properly restrict access
          to certain pages. can cause an authentication-bypass vulnerability.
        - an input passed via URL to the web administration interface is not
          properly sanitized before being returned to the user.";

  tag_summary = "This host is running MailScan a Mail Server, which is prone to
  multiple vulnerabilities.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = 10443;
if( ! get_port_state( port ) ) exit( 0 );

sndReq = http_get(item:"/main.dll", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if("Welcome to MicroWorld's MailScan" >!< rcvRes){
  exit(0);
}

 if(!safe_checks())
 {
	# Directory Traversal Request
        sndReq = http_get(item:"/../../../../boot.ini", port:port);
        rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

        if("HTTP/1.1 200" >< rcvRes && "[boot loader]" >< rcvRes){
                security_message(port);
        }
        exit(0);
 }

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 mailScanVer = registry_get_sz(key:"SOFTWARE\MicroWorld\C:#PROGRA~1#MAILSCAN" +
				   "#MAILSCAN.INI\General", item:"Version");
 if(!mailScanVer){
	exit(0);
 }

 # Grep for <= 5.6a
 if(egrep(pattern:"^([0-4]\..*|5\.[0-5][a-z]?|5\.6a?)$", string:mailScanVer)){
 	security_message(port);
 }
