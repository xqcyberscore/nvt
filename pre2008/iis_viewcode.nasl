# OpenVAS Vulnerability Test
# $Id: iis_viewcode.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Check for dangerous IIS default files
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
#
# Copyright:
# Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The file viewcode.asp is a default IIS files which can give a 
malicious user a lot of unnecessary information about your file 
system or source files.  Specifically, viewcode.asp can allow a
remote user to potentially read any file on a webserver hard drive.

Example,
http://target/pathto/viewcode.asp?source=../../../../../../autoexec.bat";

tag_solution = "If you do not need these files, then delete them, otherwise
use suitable access control lists to ensure that the files are not
world-readable.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10576");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0737");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("Check for dangerous IIS default files");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);   
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);
	
	
fl[0] = "/Sites/Knowledge/Membership/Inspired/ViewCode.asp";
fl[1] = "/Sites/Knowledge/Membership/Inspiredtutorial/Viewcode.asp";
fl[2] = "/Sites/Samples/Knowledge/Membership/Inspired/ViewCode.asp";
fl[3] = "/Sites/Samples/Knowledge/Membership/Inspiredtutorial/ViewCode.asp";
fl[4] = "/Sites/Samples/Knowledge/Push/ViewCode.asp";
fl[5] = "/Sites/Samples/Knowledge/Search/ViewCode.asp";
fl[6] = "/SiteServer/Publishing/viewcode.asp";
   

list = "";

for(i=0;fl[i];i=i+1)
{ 
 url = fl[i];
 if(is_cgi_installed_ka(item:url, port:port))
  {
   list = string(list, "\n", url);
  }
 }
  
if(strlen(list))
{
 mywarning = string("The following files were found on the remote\n",
 			"web server : ", list, 
  	 		"\nThese files allow anyone to read arbitrary files on the remote host\n",
    		"Example, http://your.url.com/pathto/viewcode.asp?source=../../../../autoexec.bat\n",
    		"\n\nSolution: delete these files");
 security_message(port:port, data:mywarning);
 }


