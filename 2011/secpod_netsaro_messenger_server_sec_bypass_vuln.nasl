###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netsaro_messenger_server_sec_bypass_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# NetSaro Enterprise Messenger Server Plaintext Password Storage Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902465");
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_cve_id("CVE-2011-3692", "CVE-2011-3693");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_name("NetSaro Enterprise Messenger Server Plaintext Password Storage Vulnerability");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Aug/94");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/519284");
  script_xref(name : "URL" , value : "http://www.solutionary.com/index/SERT/Vuln-Disclosures/NetSaro-Enterprise-Messenger-Vuln-Password.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 4992);
  script_family("General");
  script_tag(name : "impact" , value : "Successful exploitation could allow local attackers to access
  the configuration.xml file. Then can decrypt all username and password
  values and reuse them against other systems within the network.

  Impact Level: Application");
  script_tag(name : "affected" , value : "NetSaro Enterprise Messenger Server version 2.0 and prior.");
  script_tag(name : "insight" , value : "The flaw exists in application because it stores the username
  and password in plain text format, which allows an attacker to easily decrypt
  passwords used to authenticate to the application.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running NetSaro Enterprise Messenger Server and is
  prone to security bypass vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Check for the default port
port = get_http_port(default:4992);

## Send the request and receive response
rcvRes = http_get_cache(item:"/", port:port);

## Confirm the server
if("></NetSaroEnterpriseMessenger>" >< rcvRes)
{
  ## Grep for the version
  netsVer = eregmatch(pattern:'version="([0-9.]+)', string:rcvRes);
  if(netsVer[1] != NULL)
  {
    ## Check NetSaro Enterprise Messenger Server version 2.0 (2.1) and prior
    if(version_is_less_equal(version:netsVer[1], test_version:"2.1")){
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);