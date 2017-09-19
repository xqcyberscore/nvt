###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_event_booking_sql_injection_vuln.nasl 63129 2016-09-27 12:38:28Z Sep$
#
# Joomla! Component Event Booking SQL Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807368");
  script_version("$Revision: 7174 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-09-27 10:23:31 +0530 (Tue, 27 Sep 2016)");
  script_name("Joomla! Component Event Booking SQL Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Joomla component
  event booking and is prone to sql injection vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  validation of user supplied input via 'Date' parameter to 'index.php' 
  script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.

  Impact Level: Application");

  script_tag(name:"affected", value:"Joomla Event Booking Component version 2.10.1");

  script_tag(name:"solution", value:"Update to version 2.10.4.For updates refer to http://extensions.joomla.org/extension/event-booking");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40423");
  script_xref(name:"URL", value:"https://www.joomdonation.com/forum/events-booking-general-discussion/54939-events-booking-2-11-0-released.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
http_port = 0;
url = "";
dir = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Joomla Location
if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}
if(dir = "/"){
  dir = "";
}

## Construct the attack request
url = dir + "/index.php?option=com_eventbooking&view=calendar&layout" + 
            "=weekly&date=%27SQL-INJECTION-TEST&Itemid=354#";

## Check the response to confirm vulnerability
## check_header is not 200 OK
if(http_vuln_check(port:http_port, url:url,
                   pattern:"You have an error in your SQL syntax",
                   extra_check:make_list('SQL-INJECTION-TEST',
                   '>1064 - Error: 1064<', 'FROM #__eb_events AS')))
{
  report = report_vuln_url(port:http_port, url:url);
  security_message(port:http_port, data:report);
  exit(0);
}
