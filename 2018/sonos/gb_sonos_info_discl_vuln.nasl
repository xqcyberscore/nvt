##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonos_info_discl_vuln.nasl 10688 2018-07-31 06:55:11Z asteins $
#
# Sonos Speaker Information Disclosure Vulnerability
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

CPE = 'cpe:/a:sonos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141020");
  script_version("$Revision: 10688 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-31 08:55:11 +0200 (Tue, 31 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-04-24 10:15:48 +0700 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Sonos Speaker Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sonos_detect.nasl");
  script_mandatory_keys("sonos_speaker/detected");

  script_tag(name:"summary", value:"Sonos Speakers are prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"By accessing /status or /tools it is possible for an unauthenticated attacker
to gather information about the device settings and possible other information. This may lead to further
attacks.");

  script_tag(name:"solution", value:"No known solution is available as of 31st July, 2018. Information
regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://conference.hitb.org/hitbsecconf2018ams/materials/D1%20COMMSEC%20-%20Stephen%20Hilt%20-%20Hacking%20IoT%20Speakers.pdf");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port_from_cpe_prefix(cpe: CPE))
  exit(0);

url = "/status/topology";
if (http_vuln_check(port: port, url: url, pattern: "<ZPSupportInfo><ZonePlayers>", check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
