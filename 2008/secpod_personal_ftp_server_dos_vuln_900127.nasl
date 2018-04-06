##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_personal_ftp_server_dos_vuln_900127.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Personal FTP Server RETR Command Remote Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will deny the service by sending
        multiple RETR commands with an arbitrary argument.
 Impact Level : Application";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.
For updates refer to http://www.michael-roth-software.de/new/Produkte.html";

tag_affected = "Michael Roth Personal FTP Server 6.0f and prior on Windows (all).";

tag_insight = "This issue is due to an error when handling the RETR command.";


tag_summary = "The host is running Personal FTP Server, which is prone to denial
 of service vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900127");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_cve_id("CVE-2008-4136");
 script_bugtraq_id(31173);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Denial of Service");
 script_name("Personal FTP Server RETR Command Remote Denial of Service Vulnerability");

 script_dependencies("secpod_reg_enum.nasl", "find_service.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports("Services/ftp", 21, 139, 445);
 script_xref(name : "URL" , value : "http://shinnok.evonet.ro/vulns_html/pftp.html");
 script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/31173.c");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name:"solution_type", value:"WillNotFix");
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }
 
 port = get_kb_item("Services/ftp");
 if(!port){
        port = 21;
 }

 if(!get_port_state(port)){
        exit(0);
 }

 pftpVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\Uninstall\The Personal FTP Server_is1",
                           item:"DisplayVersion");

 if(egrep(pattern:"^([0-5]\..*|6\.0([a-f])?)$", string:pftpVer)){
        security_message(port);
 }
