###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-070_remote.nasl 6005 2017-04-21 13:14:30Z cfi $
#
# Microsoft ASP.NET Information Disclosure Vulnerability (2418042)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901161");
  script_version("$Revision: 6005 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-21 15:14:30 +0200 (Fri, 21 Apr 2017) $");
  script_tag(name:"creation_date", value:"2010-09-29 13:56:35 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3332");
  script_bugtraq_id(43316);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Microsoft ASP.NET Information Disclosure Vulnerability (2418042)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2429");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS10-070.mspx");
  script_xref(name:"URL", value:"http://www.troyhunt.com/2010/09/fear-uncertainty-and-and-padding-oracle.html");
  script_xref(name:"URL", value:"http://weblogs.asp.net/scottgu/archive/2010/09/18/important-asp-net-security-vulnerability.aspx");

  tag_impact = "Successful exploitation could allow remote attackers to decrypt and gain
  access to potentially sensitive data encrypted by the server or read data from arbitrary
  files within an ASP.NET application. Obtained information may aid in further attacks.

  Impact Level: System/Application";

  tag_affected = "Microsoft ASP.NET 1.0
  Microsoft ASP.NET 4.0
  Microsoft ASP.NET 3.5.1
  Microsoft ASP.NET 1.1 SP1 and prior
  Microsoft ASP.NET 2.0 SP2 and prior
  Microsoft ASP.NET 3.5 SP1 and prior";

  tag_insight = "The flaw is due to an error within ASP.NET in the handling of
  cryptographic padding when using encryption in CBC mode. This can be
  exploited to decrypt data via returned error codes from an affected server.";

  tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-070.mspx";

  tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-070.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if( ! can_host_asp( port:port ) ) exit( 0 );

## Send and Receive the response
res = http_get_cache(item:"/default.aspx", port:port);

## Confirm ASP.NET Installed
if(res && "X-Powered-By: ASP.NET" >< res &&
   !(ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 Internal Server Error", string:res)))
{
  ## Try to access WebResource.axd without parameters to confirm we will not get
  ## 500 Internal Server Error, else it will create false positive
  req1 = http_get(item:string("/WebResource.axd"), port:port);
  res1 = http_keepalive_send_recv(port:port, data:req1);

  if(res1 && !(ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 Internal Server Error", string:res1)))
  {
    ## Try to access WebResource.axd
    req = http_get(item:string("/WebResource.axd?d="+rand()+"&t="+rand()), port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    ## Check for Status Code 500
    if(res && ereg(pattern:"^HTTP/[0-9]\.[0-9] 500 .*", string:res)){
      security_message(port);
    }
  }
}
