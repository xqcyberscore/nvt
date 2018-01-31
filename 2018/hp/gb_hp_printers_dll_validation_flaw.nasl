###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printers_dll_validation_flaw.nasl 8580 2018-01-30 10:27:25Z jschulte $
#
# HP Printers Insufficient DLL Signature Validation
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113095");
  script_version("$Revision: 8580 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-30 11:27:25 +0100 (Tue, 30 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-26 14:20:42 +0100 (Fri, 26 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2750");
  script_bugtraq_id(101965);

  script_name("HP Printers Insufficient DLL Signature Validation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Multiple HP Printers perform insufficient Solution DLL Signature Validation, allowing for potential execution of arbitrary code.");
  script_tag(name:"vuldetect", value:"The script checks if the target host is a vulnerable device running a vulnerable firmware version.");
  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control over the target host.");
  script_tag(name:"affected", value:"Following devices and firmware versions are affected:

  FutureSmart 3:

  Firmware versions through 2308937_578506: HP Color LaserJet CM4530 MFP

  Firmware versions through 2308937_578507: HP Color LaserJet CP5525

  Firmware versions through 2308937_578486: HP Color LaserJet Enterprise M552, HP Color LaserJet Enterprise M553

  Firmware versions through 2308937_578496: HP Color LaserJet Enterprise M651

  Firmware versions through 2308937_578500: HP Color LaserJet Enterprise M750

  Firmware versions through 2308937_578487: HP Color LaserJet Enterprise MFP M577

  Firmware versions through 2308937_578495: HP Color LaserJet Enterprise MFP M680

  Firmware versions through 2308937_578501: HP LaserJet Enterprise 500 color MFP M575, HP LaserJet Enterprise color flow MFP M575

  Firmware versions through 2308937_578492: HP LaserJet Enterprise 500 MFP M525, HP LaserJet Enterprise flow MFP 525

  Firmware versions through 2308937_578502: HP LaserJet Enterprise 600 M601, HP LaserJet Enterprise 600 M602, HP LaserJet Enterprise 600 M603

  Firmware versions through 2308937_578504: HP LaserJet Enterprise 700 color MFP M775 series

  Firmware versions through 2308937_578503: HP LaserJet Enterprise 700 M712

  Firmware versions through 2308937_578498: HP LaserJet Enterprise 800 color M855

  Firmware versions through 2308937_578493: HP LaserJet Enterprise 800 color MFP M880

  Firmware versions through 2308937_578505: HP LaserJet Enterprise Color 500 M551 Series

  Firmware versions through 2308937_578494: HP LaserJet Enterprise flow M830z MFP

  Firmware versions through 2308937_578478: HP LaserJet Enterprise Flow MFP M630, HP LaserJet Enterprise MFP M630

  Firmware versions through 2308937_578483: HP LaserJet Enterprise M4555 MFP

  Firmware versions through 2308937_578488: HP LaserJet Enterprise M506

  Firmware versions through 2308937_578484: HP LaserJet Enterprise M527

  Firmware versions through 2308937_578489: HP LaserJet Enterprise M604, HP LaserJet Enterprise M605, HP LaserJet Enterprise M606

  Firmware versions through 2308937_578499: HP LaserJet Enterprise M806

  Firmware versions through 2308937_578497: HP LaserJet Enterprise MFP M725

  Firmware versions through 2308937_578482: HP OfficeJet Enterprise Color Flow MFP X585, HP OfficeJet Enterprise Color MFP X585, HP Digital Sender Flow 8500 fn2 Document Capture Workstation

  Firmware versions through 2308937_578481: HP OfficeJet Enterprise Color X555

  Firmware versions through 2308937_578491: HP PageWide Enterprise Color MFP 586, HP PageWide Managed Color Flow MFP 586, HP PageWide Managed Color Flow MFP E58650, HP PageWide Managed Color MFP E58650

  Firmware versions through 2308937_578490: HP PageWide Enterprise Color X556, HP PageWide Managed Color E55650

  Firmware versions thorugh 2308937_578486: HP Scanjet Enterprise 8500 Document Capture Workstation




  FutureSmart 4:

  Firmware versions through 2405129_000036: HP Color LaserJet Enterprise Flow MFP M681f, HP Color LaserJet Enterprise Flow MFP M682, HP Color LaserJet Enterprise MFP M681, HP Color LaserJet Enterprise MFP M682, HP Color LaserJet Managed Flow MFP E67560, HP Color LaserJet Managed MFP E67550dh, HP Color LaserJet Managed MFP E67560dz

  Firmware versions through 2405129_000046: HP Color LaserJet Enterprise M561

  Firmware versions through 2405130_000067: HP Color LaserJet Enterprise M652, HP Color LaserJet Enterprise M563, HP Color LaserJet Managed E65050, HP Color LaserJet Managed E65060

  Firmware versions through 2405129_000037: HP Color LaserJet Enterprise MFP M577

  Firmware versions through 2405129_000041: HP Color LaserJet Enterprise MFP M680

  Firmware versions through 2405129_000044: HP LaserJet Enterprise 500 color MFP M575, HP LaserJet Enterprise color flow MFP M575

  Firmware versions through 2405129_000047: HP LaserJet Enterprise 500 MFP M525, HP LaserJet Enterprise flow MFP M525

  Firmware versions through 2405129_000056: HP LaserJet Enterprise 800 color M855

  Firmware versions through 2405129_000053: HP LaserJet Enterprise 800 color MFP M880

  Firmware versions through 2405129_000059: HP LaserJet Enterprise flow M830z MFP

  Firmware versions through 2405129_000039: HP LaserJet Enterprise Flow MFP M630, HP LaserJet Enterprise MFP M630

  Firmware versions through 2405129_000040: HP LaserJet Enterprise Flow MFP M631, HP LaserJet Enterprise Flow MFP M632z, HP LaserJet Enterprise Flow MFP M633z, HP LaserJet Enterprise MFP M631, HP LaserJet Enterprise MFP M632, HP LaserJet Enterprise MFP M633, HP LaserJet Managed Flow MFP E62565h, HP LaserJet Managed Flow MFP E62565z, HP LaserJet Managed Flow MFP E62575z, HP LaserJet Managed MFP E62555dn, HP LaserJet Managed MFP E62565hs

  Firmware versions through 2405129_000038: HP LaserJet Enterprise M527

  Firmware versions through 2405130_000068: HP LaserJet Enterprise M607, HP LaserJet Enterprise M608, HP LaserJet Enterprise M609d, HP LaserJet Managed E60055dn, HP LaserJet Managed E60065, HP LaserJet Managed E60075

  Firmware versions through 2405129_000058: HP LaserJet Enterprise M806

  Firmware versions through 2405129_000057: HP LaserJet Enterprise MFP M725

  Firmware versions through 2405129_000049: HP OfficeJet Enterprise Color Flow MFP X585, HP OfficeJet Enterprise Color MFP X585

  Firmware versions through 2405087_018563: HP PageWide Enterprise Color 765d, HP PageWide Managed Color E75160

  Firmware versions through 2405129_000065: HP PageWide Enterprise Color MFP 586, HP PageWide Managed Color Flow MFP 586, HP PageWide Managed Color Flow MFP E58650, HP PageWide Managed Color MFP E58650

  Firmware versions through 2405087_018547: HP PageWide Enterprise Color MPF 780, HP PageWide Enterprise Color MPF 785, HP PageWide Managed Color Flow MFP E77650, HP PageWide Managed Color Flow MFP E77660, HP PageWide Managed Color MFP E77650

  Firmware versions through 2405129_000050: HP PageWide Enterprise Color X556, HP PageWide Managed Color E55650

  Firmware versions through 2405087_018552: HP Digital Sender Flow 8500 fn2 Document Capture Workstation

  Firmware versions through 2405087_018551: HP ScanJet Enterprise Flow N9120 Document Flatbed Scanner");

  script_tag(name:"solution", value:"Following fixed versions exist:

  FutureSmart 3:

  Firmware version 2308937_578507 and above: HP Color LaserJet CM4530 MFP

  Firmware version 2308937_578508 and above: HP Color LaserJet CP5525

  Firmware version 2308937_578487 and above: HP Color LaserJet Enterprise M552, HP Color LaserJet Enterprise M553

  Firmware version 2308937_578497 and above: HP Color LaserJet Enterprise M651

  Firmware version 2308937_578501 and above: HP Color LaserJet Enterprise M750

  Firmware version 2308937_578488 and above: HP Color LaserJet Enterprise MFP M577

  Firmware version 2308937_578496 and above: HP Color LaserJet Enterprise MFP M680

  Firmware version 2308937_578502 and above: HP LaserJet Enterprise 500 color MFP M575, HP LaserJet Enterprise color flow MFP M575

  Firmware version 2308937_578493 and above: HP LaserJet Enterprise 500 MFP M525, HP LaserJet Enterprise flow MFP 525

  Firmware version 2308937_578503 and above: HP LaserJet Enterprise 600 M601, HP LaserJet Enterprise 600 M602, HP LaserJet Enterprise 600 M603

  Firmware version 2308937_578505 and above: HP LaserJet Enterprise 700 color MFP M775 series

  Firmware version 2308937_578504 and above: HP LaserJet Enterprise 700 M712

  Firmware version 2308937_578499 and above: HP LaserJet Enterprise 800 color M855

  Firmware version 2308937_578494 and above: HP LaserJet Enterprise 800 color MFP M880

  Firmware version 2308937_578506 and above: HP LaserJet Enterprise Color 500 M551 Series

  Firmware version 2308937_578495 and above: HP LaserJet Enterprise flow M830z MFP

  Firmware version 2308937_578479 and above: HP LaserJet Enterprise Flow MFP M630, HP LaserJet Enterprise MFP M630

  Firmware version 2308937_578484 and above: HP LaserJet Enterprise M4555 MFP

  Firmware version 2308937_578489 and above: HP LaserJet Enterprise M506

  Firmware version 2308937_578485 and above: HP LaserJet Enterprise M527

  Firmware version 2308937_578490 and above: HP LaserJet Enterprise M604, HP LaserJet Enterprise M605, HP LaserJet Enterprise M606

  Firmware version 2308937_578500 and above: HP LaserJet Enterprise M806

  Firmware version 2308937_578498 and above: HP LaserJet Enterprise MFP M725

  Firmware version 2308937_578483 and above: HP OfficeJet Enterprise Color Flow MFP X585, HP OfficeJet Enterprise Color MFP X585, HP Digital Sender Flow 8500 fn2 Document Capture Workstation

  Firmware version 2308937_578482 and above: HP OfficeJet Enterprise Color X555

  Firmware version 2308937_578492 and above: HP PageWide Enterprise Color MFP 586, HP PageWide Managed Color Flow MFP 586, HP PageWide Managed Color Flow MFP E58650, HP PageWide Managed Color MFP E58650

  Firmware version 2308937_578491 and above: HP PageWide Enterprise Color X556, HP PageWide Managed Color E55650

  Firmware version 2308937_578487 and above: HP Scanjet Enterprise 8500 Document Capture Workstation




  FutureSmart 4:

  Firmware version 2405129_000037 and above: HP Color LaserJet Enterprise Flow MFP M681f, HP Color LaserJet Enterprise Flow MFP M682, HP Color LaserJet Enterprise MFP M681, HP Color LaserJet Enterprise MFP M682, HP Color LaserJet Managed Flow MFP E67560, HP Color LaserJet Managed MFP E67550dh, HP Color LaserJet Managed MFP E67560dz

  Firmware version 2405129_000047 and above: HP Color LaserJet Enterprise M561

  Firmware version 2405130_000068 and above: HP Color LaserJet Enterprise M652, HP Color LaserJet Enterprise M563, HP Color LaserJet Managed E65050, HP Color LaserJet Managed E65060

  Firmware version 2405129_000038 and above: HP Color LaserJet Enterprise MFP M577

  Firmware version 2405129_000042 and above: HP Color LaserJet Enterprise MFP M680

  Firmware version 2405129_000045 and above: HP LaserJet Enterprise 500 color MFP M575, HP LaserJet Enterprise color flow MFP M575

  Firmware version 2405129_000048 and above: HP LaserJet Enterprise 500 MFP M525, HP LaserJet Enterprise flow MFP M525

  Firmware version 2405129_000057 and above: HP LaserJet Enterprise 800 color M855

  Firmware version 2405129_000054 and above: HP LaserJet Enterprise 800 color MFP M880

  Firmware version 2405129_000060 and above: HP LaserJet Enterprise flow M830z MFP

  Firmware version 2405129_000040 and above: HP LaserJet Enterprise Flow MFP M630, HP LaserJet Enterprise MFP M630

  Firmware version 2405129_000041 and above: HP LaserJet Enterprise Flow MFP M631, HP LaserJet Enterprise Flow MFP M632z, HP LaserJet Enterprise Flow MFP M633z, HP LaserJet Enterprise MFP M631, HP LaserJet Enterprise MFP M632, HP LaserJet Enterprise MFP M633, HP LaserJet Managed Flow MFP E62565h, HP LaserJet Managed Flow MFP E62565z, HP LaserJet Managed Flow MFP E62575z, HP LaserJet Managed MFP E62555dn, HP LaserJet Managed MFP E62565hs

  Firmware version 2405129_000039 and above: HP LaserJet Enterprise M527

  Firmware version 2405130_000069 and above: HP LaserJet Enterprise M607, HP LaserJet Enterprise M608, HP LaserJet Enterprise M609d, HP LaserJet Managed E60055dn, HP LaserJet Managed E60065, HP LaserJet Managed E60075

  Firmware version 2405129_000059 and above: HP LaserJet Enterprise M806

  Firmware version 2405129_000058 and above: HP LaserJet Enterprise MFP M725

  Firmware version 2405129_000050 and above: HP OfficeJet Enterprise Color Flow MFP X585, HP OfficeJet Enterprise Color MFP X585

  Firmware version 2405087_018564 and above: HP PageWide Enterprise Color 765d, HP PageWide Managed Color E75160

  Firmware version 2405129_000066 and above: HP PageWide Enterprise Color MFP 586, HP PageWide Managed Color Flow MFP 586, HP PageWide Managed Color Flow MFP E58650, HP PageWide Managed Color MFP E58650

  Firmware version 2405087_018548 and above: HP PageWide Enterprise Color MPF 780, HP PageWide Enterprise Color MPF 785, HP PageWide Managed Color Flow MFP E77650, HP PageWide Managed Color Flow MFP E77660, HP PageWide Managed Color MFP E77650

  Firmware version 2405129_000051 and above: HP PageWide Enterprise Color X556, HP PageWide Managed Color E55650

  Firmware version 2405087_018553 and above: HP Digital Sender Flow 8500 fn2 Document Capture Workstation

  Firmware version 2405087_018552 and above: HP ScanJet Enterprise Flow N9120 Document Flatbed Scanner");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05839270");

  exit( 0 );
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! model = get_kb_item( "hp_model" ) ) exit( 0 );
if( ! fw_ver = get_kb_item( "hp_fw_ver" ) ) exit( 0 );

if( eregmatch( pattern: "LaserJet CM4530 MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578507" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578507" );
  }
}

if( eregmatch( pattern: "LaserJet CP5525", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578508" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578508" );
  }
}

if( eregmatch( pattern: "LaserJet M55[23]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578487" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578487" );
  }
}

if( eregmatch( pattern: "LaserJet M651", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578497" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578497" );
  }
}

if( eregmatch( pattern: "LaserJet M750", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578501" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578501" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M577", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578488" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578488" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M680", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578496" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578496" );
  }
}

if( eregmatch( pattern: "LaserJet 500 color[ flow]{0,5} MFP M575", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578502" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578502" );
  }
}

if( eregmatch( pattern: "LaserJet 500 MFP M525", string: model, icase: TRUE )  || eregmatch( pattern: "LaserJet flow MFP M525", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578493" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578493" );
  }
}

if( eregmatch( pattern: "LaserJet 600 M60[123]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578503" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578503" );
  }
}

if( eregmatch( pattern: "LaserJet 700 color MFP M775", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578505" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578505" );
  }
}

if( eregmatch( pattern: "LaserJet 700 M712", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578504" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578504" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color M855", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578499" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578499" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color MFP M880", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578494" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578494" );
  }
}

if( eregmatch( pattern: "LaserJet 500 color M551", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578506" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578506" );
  }
}

if( eregmatch( pattern: "LaserJet flow M830z MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578495" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578495" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M630", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578479" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578479" );
  }
}

if( eregmatch( pattern: "LaserJet M4555 MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578484" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578484" );
  }
}

if( eregmatch( pattern: "LaserJet M506", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578489" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578489" );
  }
}

if( eregmatch( pattern: "LaserJet M527", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578485" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578485" );
  }
}

if( eregmatch( pattern: "LaserJet M60[456]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578490" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578490" );
  }
}

if( eregmatch( pattern: "LaserJet M806", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578500" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578500" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M725", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578498" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578498" );
  }
}

if( eregmatch( pattern: "OfficeJet Color[ flow]{0,5} MFP X585", string: model, icase: TRUE )  || eregmatch( pattern: "Digital Sender Flow 8500 fn2", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578483" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578483" );
  }
}

if( eregmatch( pattern: "OfficeJet color X555", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578482" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578482" );
  }
}

if( eregmatch( pattern: "PageWide Color[ flow]{0,5} MFP 586", string: model, icase: TRUE )  || eregmatch( pattern: "PageWide Color[ flow]{0,5} MFP E58650", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578491" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578491" );
  }
}

if( eregmatch( pattern: "PageWide Color X556", string: model, icase: TRUE ) || eregmatch( pattern: "PageWide Color E55650", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578487" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578487" );
  }
}


# For FutureSmart 4 devices, we have to make sure not to report fixed FutureSmart 3 devices as vulnerable. Thus "version_in_range"
if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M68[12f]{1,2}", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet MFP E675[56]0[dhz]{0,2}", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000036" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000037" );
  }
}

if( eregmatch( pattern: "LaserJet M561", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000046" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000047" );
  }
}

if( eregmatch( pattern: "LaserJet M65[23]", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet E650[56]0", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405130_000067" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405130_000068" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M577", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000037" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000038" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M680", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000041" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000042" );
  }
}

if( eregmatch( pattern: "LaserJet color[ flow]{0,5} MFP M575", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000044" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000045" );
  }
}

if( eregmatch( pattern: "LaserJet 500 MFP M525", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet flow MFP M525", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000047" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000048" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color M855", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000056" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000057" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color MFP M800", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000053" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000054" );
  }
}

if( eregmatch( pattern: "LaserJet flow M830z MFP", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000059" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000060" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M630", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000039" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000040" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M63[123z]{1,2}", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet[ flow]{0,5} MFP E625[567]5[dhsz]{1,2}", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000040" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000041" );
  }
}

if( eregmatch( pattern: "LaserJet M527", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000038" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000039" );
  }
}

if( eregmatch( pattern: "LaserJet M60[789][d]{0,1}", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet E600[567]5[dn]{0,2}", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405130_000068" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405130_000069" );
  }
}

if( eregmatch( pattern: "LaserJet M806", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000058" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000059" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M725", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000057" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000058" );
  }
}

if( eregmatch( pattern: "LaserJet color[ flow]{0,5} MFP X585", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000049" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000050" );
  }
}

if( eregmatch( pattern: "PageWide Color 765d", string: model, icase: TRUE ) || eregmatch( pattern: "PageWide Color E55650", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000050" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000051" );
  }
}

if( eregmatch( pattern: "Digital Sender Flow 8500 fn2", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405087_018552" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405087_018553" );
  }
}

if( eregmatch( pattern: "ScanJet Flow N9120", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405087_018551" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405087_018552" );
  }
}

if( ! isnull( report ) ) {
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
