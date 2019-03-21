##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_nakid_cms_rfi_vuln.nasl 14326 2019-03-19 13:40:32Z jschulte $
#
# Nakid CMS 'core[system_path]' Parameter Remote File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902082");
  script_version("$Revision: 14326 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:40:32 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-2358");
  script_bugtraq_id(40882);
  script_name("Nakid CMS 'core[system_path]' Parameter Remote File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40174");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59453");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/13889/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/1498");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_nakid_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"insight", value:"The flaw is caused by an input validation error in the
'/modules/catalog/upload_photo.php' script when processing the
'core[system_path]' parameter.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Nakid CMS and is prone to remote file
inclusion vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to include malicious
PHP scripts and execute arbitrary commands with the privileges of the web server.");
  script_tag(name:"affected", value:"Nakid CMS version 0.5.2 and 0.5.1");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");

ncPort = get_http_port(default:80);
if(!ncPort){
  exit(0);
}

ncVer = get_kb_item("www/" + ncPort + "/Nakid/CMS/Ver");
if(!ncVer){
 exit(0);
}

ncVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ncVer);
if(!isnull(ncVer[2]))
{
  sndReq = http_get(item:string(ncVer[2], "/modules/catalog/upload_photo.php?" +
                                  "core[system_path]=OpenVAS_RFI.php"), port:ncPort);
  rcvRes = http_send_recv(port:ncPort, data:sndReq);
  if("OpenVAS_RFI.php" >< rcvRes && "failed to open stream" >< rcvRes){
    security_message(ncPort);
  }
}
