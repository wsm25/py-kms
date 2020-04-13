import binascii
import datetime
import filetimes
import kmsPidGenerator
import struct
import uuid

from structure import Structure

class UUID(Structure):
	commonHdr = ()
	structure = (
		('raw', '16s'),
	)

	def get(self):
		return uuid.UUID(bytes_le=str(self))

class kmsBase:
	class kmsRequestStruct(Structure):
		commonHdr = ()
		structure = (
			('versionMinor',            '<H'),
			('versionMajor',            '<H'),
			('isClientVm',              '<I'),
			('licenseStatus',           '<I'),
			('graceTime',               '<I'),
			('applicationId',           ':', UUID),
			('skuId',                   ':', UUID),
			('kmsCountedId' ,           ':', UUID),
			('clientMachineId',         ':', UUID),
			('requiredClientCount',     '<I'),
			('requestTime',             '<Q'),
			('previousClientMachineId', ':', UUID),
			('machineName',             'u'),
			('_mnPad',                  '_-mnPad', '126-len(machineName)'),
			('mnPad',                   ':'),
		)

		def getMachineName(self):
			return self['machineName'].decode('utf-16le')

		def getLicenseStatus(self):
			return kmsBase.licenseStates[self['licenseStatus']] or "Unknown"

	class kmsResponseStruct(Structure):
		commonHdr = ()
		structure = (
			('versionMinor',         '<H'),
			('versionMajor',         '<H'),
			('epidLen',              '<I=len(kmsEpid)+2'),
			('kmsEpid',              'u'),
			('clientMachineId',      ':', UUID),
			('responseTime',         '<Q'),
			('currentClientCount',   '<I'),
			('vLActivationInterval', '<I'),
			('vLRenewalInterval',    '<I'),
		)

	class GenericRequestHeader(Structure):
		commonHdr = ()
		structure = (
			('bodyLength1',  '<I'),
			('bodyLength2',  '<I'),
			('versionMinor', '<H'),
			('versionMajor', '<H'),
			('remainder',    '_'),
		)

	appIds = {
		uuid.UUID("55C92734-D682-4D71-983E-D6EC3F16059F") : "Windows",
		uuid.UUID("59A52881-A989-479D-AF46-F275C6370663") : "Office 14 (2010)",
		uuid.UUID("0FF1CE15-A989-479D-AF46-F275C6370663") : "Office 15 (2013)",
		uuid.UUID("0FF1CE15-A989-479D-AF46-F275C6370663") : "Office 16 (2016)",
	}

	skuIds = {
		uuid.UUID("ad2542d4-9154-4c6d-8a44-30f11ee96989") : "Windows Server 2008 Standard",
		uuid.UUID("2401e3d0-c50a-4b58-87b2-7e794b7d2607") : "Windows Server 2008 StandardV",
		uuid.UUID("68b6e220-cf09-466b-92d3-45cd964b9509") : "Windows Server 2008 Datacenter",
		uuid.UUID("fd09ef77-5647-4eff-809c-af2b64659a45") : "Windows Server 2008 DatacenterV",
		uuid.UUID("c1af4d90-d1bc-44ca-85d4-003ba33db3b9") : "Windows Server 2008 Enterprise",
		uuid.UUID("8198490a-add0-47b2-b3ba-316b12d647b4") : "Windows Server 2008 EnterpriseV",
		uuid.UUID("ddfa9f7c-f09e-40b9-8c1a-be877a9a7f4b") : "Windows Server 2008 Web",
		uuid.UUID("7afb1156-2c1d-40fc-b260-aab7442b62fe") : "Windows Server 2008 ComputerCluster",
		uuid.UUID("68531fb9-5511-4989-97be-d11a0f55633f") : "Windows Server 2008 R2 Standard",
		uuid.UUID("7482e61b-c589-4b7f-8ecc-46d455ac3b87") : "Windows Server 2008 R2 Datacenter",
		uuid.UUID("620e2b3d-09e7-42fd-802a-17a13652fe7a") : "Windows Server 2008 R2 Enterprise",
		uuid.UUID("a78b8bd9-8017-4df5-b86a-09f756affa7c") : "Windows Server 2008 R2 Web",
		uuid.UUID("cda18cf3-c196-46ad-b289-60c072869994") : "Windows Server 2008 R2 ComputerCluster",
		uuid.UUID("d3643d60-0c42-412d-a7d6-52e6635327f6") : "Windows Server 2012 Datacenter",
		uuid.UUID("f0f5ec41-0d55-4732-af02-440a44a3cf0f") : "Windows Server 2012 Standard",
		uuid.UUID("95fd1c83-7df5-494a-be8b-1300e1c9d1cd") : "Windows Server 2012 MultiPoint Premium",
		uuid.UUID("7d5486c7-e120-4771-b7f1-7b56c6d3170c") : "Windows Server 2012 MultiPoint Standard",
		uuid.UUID("00091344-1ea4-4f37-b789-01750ba6988c") : "Windows Server 2012 R2 Datacenter",
		uuid.UUID("b3ca044e-a358-4d68-9883-aaa2941aca99") : "Windows Server 2012 R2 Standard",
		uuid.UUID("b743a2be-68d4-4dd3-af32-92425b7bb623") : "Windows Server 2012 R2 Cloud Storage",
		uuid.UUID("21db6ba4-9a7b-4a14-9e29-64a60c59301d") : "Windows Server Essentials 2012 R2",
		uuid.UUID("81671aaf-79d1-4eb1-b004-8cbbe173afea") : "Windows 8.1 Enterprise",
		uuid.UUID("113e705c-fa49-48a4-beea-7dd879b46b14") : "Windows 8.1 EnterpriseN",
		uuid.UUID("096ce63d-4fac-48a9-82a9-61ae9e800e5f") : "Windows 8.1 Professional WMC",
		uuid.UUID("c06b6981-d7fd-4a35-b7b4-054742b7af67") : "Windows 8.1 Professional",
		uuid.UUID("7476d79f-8e48-49b4-ab63-4d0b813a16e4") : "Windows 8.1 ProfessionalN",
		uuid.UUID("fe1c3238-432a-43a1-8e25-97e7d1ef10f3") : "Windows 8.1 Core",
		uuid.UUID("78558a64-dc19-43fe-a0d0-8075b2a370a3") : "Windows 8.1 CoreN",
		uuid.UUID("a00018a3-f20f-4632-bf7c-8daa5351c914") : "Windows 8 Professional WMC",
		uuid.UUID("a98bcd6d-5343-4603-8afe-5908e4611112") : "Windows 8 Professional",
		uuid.UUID("ebf245c1-29a8-4daf-9cb1-38dfc608a8c8") : "Windows 8 ProfessionalN",
		uuid.UUID("458e1bec-837a-45f6-b9d5-925ed5d299de") : "Windows 8 Enterprise",
		uuid.UUID("e14997e7-800a-4cf7-ad10-de4b45b578db") : "Windows 8 EnterpriseN",
		uuid.UUID("c04ed6bf-55c8-4b47-9f8e-5a1f31ceee60") : "Windows 8 Core",
		uuid.UUID("197390a0-65f6-4a95-bdc4-55d58a3b0253") : "Windows 8 CoreN",
		uuid.UUID("ae2ee509-1b34-41c0-acb7-6d4650168915") : "Windows 7 Enterprise",
		uuid.UUID("1cb6d605-11b3-4e14-bb30-da91c8e3983a") : "Windows 7 EnterpriseN",
		uuid.UUID("b92e9980-b9d5-4821-9c94-140f632f6312") : "Windows 7 Professional",
		uuid.UUID("54a09a0d-d57b-4c10-8b69-a842d6590ad5") : "Windows 7 ProfessionalN",
		uuid.UUID("cfd8ff08-c0d7-452b-9f60-ef5c70c32094") : "Windows Vista Enterprise",
		uuid.UUID("d4f54950-26f2-4fb4-ba21-ffab16afcade") : "Windows Vista EnterpriseN",
		uuid.UUID("4f3d1606-3fea-4c01-be3c-8d671c401e3b") : "Windows Vista Business",
		uuid.UUID("2c682dc2-8b68-4f63-a165-ae291d4cf138") : "Windows Vista BusinessN",
		uuid.UUID("aa6dd3aa-c2b4-40e2-a544-a6bbb3f5c395") : "Windows ThinPC",
		uuid.UUID("db537896-376f-48ae-a492-53d0547773d0") : "Windows Embedded POSReady 7",
		uuid.UUID("0ab82d54-47f4-4acb-818c-cc5bf0ecb649") : "Windows Embedded Industry 8.1",
		uuid.UUID("cd4e2d9f-5059-4a50-a92d-05d5bb1267c7") : "Windows Embedded IndustryE 8.1",
		uuid.UUID("f7e88590-dfc7-4c78-bccb-6f3865b99d1a") : "Windows Embedded IndustryA 8.1",
		uuid.UUID("8ce7e872-188c-4b98-9d90-f8f90b7aad02") : "Office Access 2010",
		uuid.UUID("cee5d470-6e3b-4fcc-8c2b-d17428568a9f") : "Office Excel 2010",
		uuid.UUID("8947d0b8-c33b-43e1-8c56-9b674c052832") : "Office Groove 2010",
		uuid.UUID("ca6b6639-4ad6-40ae-a575-14dee07f6430") : "Office InfoPath 2010",
		uuid.UUID("09ed9640-f020-400a-acd8-d7d867dfd9c2") : "Office Mondo 2010",
		uuid.UUID("ef3d4e49-a53d-4d81-a2b1-2ca6c2556b2c") : "Office Mondo 2010",
		uuid.UUID("ab586f5c-5256-4632-962f-fefd8b49e6f4") : "Office OneNote 2010",
		uuid.UUID("ecb7c192-73ab-4ded-acf4-2399b095d0cc") : "Office OutLook 2010",
		uuid.UUID("45593b1d-dfb1-4e91-bbfb-2d5d0ce2227a") : "Office PowerPoint 2010",
		uuid.UUID("df133ff7-bf14-4f95-afe3-7b48e7e331ef") : "Office Project Pro 2010",
		uuid.UUID("5dc7bf61-5ec9-4996-9ccb-df806a2d0efe") : "Office Project Standard 2010",
		uuid.UUID("b50c4f75-599b-43e8-8dcd-1081a7967241") : "Office Publisher 2010",
		uuid.UUID("92236105-bb67-494f-94c7-7f7a607929bd") : "Office Visio Premium 2010",
		uuid.UUID("e558389c-83c3-4b29-adfe-5e4d7f46c358") : "Office Visio Pro 2010",
		uuid.UUID("9ed833ff-4f92-4f36-b370-8683a4f13275") : "Office Visio Standard 2010",
		uuid.UUID("2d0882e7-a4e7-423b-8ccc-70d91e0158b1") : "Office Word 2010",
		uuid.UUID("6f327760-8c5c-417c-9b61-836a98287e0c") : "Office Professional Plus 2010",
		uuid.UUID("9da2a678-fb6b-4e67-ab84-60dd6a9c819a") : "Office Standard 2010",
		uuid.UUID("ea509e87-07a1-4a45-9edc-eba5a39f36af") : "Office Small Business Basics 2010",
		uuid.UUID("6ee7622c-18d8-4005-9fb7-92db644a279b") : "Office Access 2013",
		uuid.UUID("f7461d52-7c2b-43b2-8744-ea958e0bd09a") : "Office Excel 2013",
		uuid.UUID("a30b8040-d68a-423f-b0b5-9ce292ea5a8f") : "Office InfoPath 2013",
		uuid.UUID("1b9f11e3-c85c-4e1b-bb29-879ad2c909e3") : "Office Lync 2013",
		uuid.UUID("dc981c6b-fc8e-420f-aa43-f8f33e5c0923") : "Office Mondo 2013",
		uuid.UUID("efe1f3e6-aea2-4144-a208-32aa872b6545") : "Office OneNote 2013",
		uuid.UUID("771c3afa-50c5-443f-b151-ff2546d863a0") : "Office OutLook 2013",
		uuid.UUID("8c762649-97d1-4953-ad27-b7e2c25b972e") : "Office PowerPoint 2013",
		uuid.UUID("4a5d124a-e620-44ba-b6ff-658961b33b9a") : "Office Project Pro 2013",
		uuid.UUID("427a28d1-d17c-4abf-b717-32c780ba6f07") : "Office Project Standard 2013",
		uuid.UUID("00c79ff1-6850-443d-bf61-71cde0de305f") : "Office Publisher 2013",
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office Visio Standard 2013",
		uuid.UUID("e13ac10e-75d0-4aff-a0cd-764982cf541c") : "Office Visio Pro 2013",
		uuid.UUID("d9f5b1c6-5386-495a-88f9-9ad6b41ac9b3") : "Office Word 2013",
		uuid.UUID("b322da9c-a2e2-4058-9e4e-f59a6970bd69") : "Office Professional Plus 2013",
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office Standard 2013",
		# the new ones
		uuid.UUID("85dd8b5f-eaa4-4af3-a628-cce9e77c9a03") : "Office 2019 Professional Plus", #NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP
		uuid.UUID("6912a74b-a5fb-401a-bfdb-2e3ab46f4b02") : "Office 2019 Standard", #6NWWJ-YQWMR-QKGCB-6TMB3-9D9HK
		uuid.UUID("2ca2bf3f-949e-446a-82c7-e25a15ec78c4") : "Project 2019 Professional", #B4NPR-3FKK7-T2MBV-FRQ4W-PKD2B
		uuid.UUID("1777f0e3-7392-4198-97ea-8ae4de6f6381") : "Project 2019 Standard", #C4F7P-NCP8C-6CQPT-MQHV9-JXD2M
		uuid.UUID("5b5cf08f-b81a-431d-b080-3450d8620565") : "Visio 2019 Professional", #9BGNQ-K37YR-RQHF2-38RQ3-7VCBB
		uuid.UUID("e06d7df3-aad0-419d-8dfb-0ac37e2bdf39") : "Visio 2019 Standard", #7TQNQ-K3YQQ-3PFH7-CCPPM-X4VQ2
		uuid.UUID("9e9bceeb-e736-4f26-88de-763f87dcc485") : "Access 2019", #9N9PT-27V4Y-VJ2PD-YXFMF-YTFQT
		uuid.UUID("237854e9-79fc-4497-a0c1-a70969691c6b") : "Excel 2019", #TMJWT-YYNMB-3BKTF-644FC-RVXBD
		uuid.UUID("c8f8a301-19f5-4132-96ce-2de9d4adbd33") : "Outlook 2019", #7HD7K-N4PVK-BHBCQ-YWQRW-XW4VK
		uuid.UUID("3131fd61-5e4f-4308-8d6d-62be1987c92c") : "PowerPoint 2019", #RRNCX-C64HY-W2MM7-MCH9G-TJHMQ
		uuid.UUID("9d3e4cca-e172-46f1-a2f4-1d2107051444") : "Publisher 2019", #G2KWX-3NW6P-PY93R-JXK2T-C9Y9V
		uuid.UUID("734c6c6e-b0ba-4298-a891-671772b2bd1b") : "Skype for Business 2019", #NCJ33-JHBBY-HTK98-MYCV8-HMKHJ
		uuid.UUID("059834fe-a8ea-4bff-b67b-4d006b5447d3") : "Word 2019", #PBX3G-NWMT6-Q7XBW-PYJGG-WXD33
		uuid.UUID("0bc88885-718c-491d-921f-6f214349e79c") : "Office 2019 Professional Plus C2R-P", #VQ9DP-NVHPH-T9HJC-J9PDT-KTQRG
		uuid.UUID("fc7c4d0c-2e85-4bb9-afd4-01ed1476b5e9") : "Project 2019 Professional C2R-P", #XM2V9-DN9HH-QB449-XDGKC-W2RMW
		uuid.UUID("500f6619-ef93-4b75-bcb4-82819998a3ca") : "Visio 2019 Professional C2R-P", #N2CG9-YD3YK-936X4-3WR82-Q3X4H
		uuid.UUID("9caabccb-61b1-4b4b-8bec-d10a3c3ac2ce") : "Office 2016 Mondo", #HFTND-W9MK4-8B7MJ-B6C4G-XQBR2
		uuid.UUID("d450596f-894d-49e0-966a-fd39ed4c4c64") : "Office 2016 Professional Plus", #XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99
		uuid.UUID("dedfa23d-6ed1-45a6-85dc-63cae0546de6") : "Office 2016 Standard", #JNRGM-WHDWX-FJJG3-K47QV-DRTFM
		uuid.UUID("4f414197-0fc2-4c01-b68a-86cbb9ac254c") : "Project 2016 Professional", #YG9NW-3K39V-2T3HJ-93F3Q-G83KT
		uuid.UUID("da7ddabc-3fbe-4447-9e01-6ab7440b4cd4") : "Project 2016 Standard", #GNFHQ-F6YQM-KQDGJ-327XX-KQBVC
		uuid.UUID("6bf301c1-b94a-43e9-ba31-d494598c47fb") : "Visio 2016 Professional", #PD3PC-RHNGV-FXJ29-8JK7D-RJRJK
		uuid.UUID("aa2a7821-1827-4c2c-8f1d-4513a34dda97") : "Visio 2016 Standard", #7WHWN-4T7MP-G96JF-G33KR-W8GF4
		uuid.UUID("67c0fc0c-deba-401b-bf8b-9c8ad8395804") : "Access 2016", #GNH9Y-D2J4T-FJHGG-QRVH7-QPFDW
		uuid.UUID("c3e65d36-141f-4d2f-a303-a842ee756a29") : "Excel 2016", #9C2PK-NWTVB-JMPW8-BFT28-7FTBF
		uuid.UUID("d8cace59-33d2-4ac7-9b1b-9b72339c51c8") : "OneNote 2016", #DR92N-9HTF2-97XKM-XW2WJ-XW3J6
		uuid.UUID("ec9d9265-9d1e-4ed0-838a-cdc20f2551a1") : "Outlook 2016", #R69KK-NTPKF-7M3Q4-QYBHW-6MT9B
		uuid.UUID("d70b1bba-b893-4544-96e2-b7a318091c33") : "PowerPoint 2016", #J7MQP-HNJ4Y-WJ7YM-PFYGF-BY6C6
		uuid.UUID("041a06cb-c5b8-4772-809f-416d03d16654") : "Publisher 2016", #F47MM-N3XJP-TQXJ9-BP99D-8K837
		uuid.UUID("83e04ee1-fa8d-436d-8994-d31a862cab77") : "Skype for Business 2016", #869NQ-FJ69K-466HW-QYCP2-DDBV6
		uuid.UUID("bb11badf-d8aa-470e-9311-20eaf80fe5cc") : "Word 2016", #WXY84-JN2Q9-RBCCQ-3Q3J3-3PFJ6
		uuid.UUID("829b8110-0e6f-4349-bca4-42803577788d") : "Project 2016 Professional C2R-P", #WGT24-HCNMF-FQ7XH-6M8K7-DRTW9
		uuid.UUID("cbbaca45-556a-4416-ad03-bda598eaa7c8") : "Project 2016 Standard C2R-P", #D8NRQ-JTYM3-7J2DX-646CT-6836M
		uuid.UUID("b234abe3-0857-4f9c-b05a-4dc314f85557") : "Visio 2016 Professional C2R-P", #69WXN-MBYV6-22PQG-3WGHK-RM6XC
		uuid.UUID("361fe620-64f4-41b5-ba77-84f8e079b1f7") : "Visio 2016 Standard C2R-P", #NY48V-PPYYH-3F4PX-XJRKJ-W4423
		uuid.UUID("e914ea6e-a5fa-4439-a394-a9bb3293ca09") : "Office 2016 MondoR Automation", #DMTCJ-KNRKX-26982-JYCKT-P7KB6
		uuid.UUID("dc981c6b-fc8e-420f-aa43-f8f33e5c0923") : "Office 2013 Mondo", #42QTK-RN8M7-J3C4G-BBGYM-88CYV
		uuid.UUID("b322da9c-a2e2-4058-9e4e-f59a6970bd69") : "Office 2013 Professional Plus", #YC7DK-G2NP3-2QQC3-J6H88-GVGXT
		uuid.UUID("b13afb38-cd79-4ae5-9f7f-eed058d750ca") : "Office 2013 Standard", #KBKQT-2NMXY-JJWGP-M62JB-92CD4
		uuid.UUID("4a5d124a-e620-44ba-b6ff-658961b33b9a") : "Project 2013 Professional", #FN8TT-7WMH6-2D4X9-M337T-2342K
		uuid.UUID("427a28d1-d17c-4abf-b717-32c780ba6f07") : "Project 2013 Standard", #6NTH3-CW976-3G3Y2-JK3TX-8QHTT
		uuid.UUID("e13ac10e-75d0-4aff-a0cd-764982cf541c") : "Visio 2013 Professional", #C2FG9-N6J68-H8BTJ-BW3QX-RM3B3
		uuid.UUID("ac4efaf0-f81f-4f61-bdf7-ea32b02ab117") : "Visio 2013 Standard", #J484Y-4NKBF-W2HMG-DBMJC-PGWR7
		uuid.UUID("6ee7622c-18d8-4005-9fb7-92db644a279b") : "Access 2013", #NG2JY-H4JBT-HQXYP-78QH9-4JM2D
		uuid.UUID("f7461d52-7c2b-43b2-8744-ea958e0bd09a") : "Excel 2013", #VGPNG-Y7HQW-9RHP7-TKPV3-BG7GB
		uuid.UUID("fb4875ec-0c6b-450f-b82b-ab57d8d1677f") : "OneDrive for Business 2013 (Groove)", #H7R7V-WPNXQ-WCYYC-76BGV-VT7GH
		uuid.UUID("a30b8040-d68a-423f-b0b5-9ce292ea5a8f") : "InfoPath 2013", #DKT8B-N7VXH-D963P-Q4PHY-F8894
		uuid.UUID("1b9f11e3-c85c-4e1b-bb29-879ad2c909e3") : "Lync 2013", #2MG3G-3BNTT-3MFW9-KDQW3-TCK7R
		uuid.UUID("efe1f3e6-aea2-4144-a208-32aa872b6545") : "OneNote 2013", #TGN6P-8MMBC-37P2F-XHXXK-P34VW
		uuid.UUID("771c3afa-50c5-443f-b151-ff2546d863a0") : "Outlook 2013", #QPN8Q-BJBTJ-334K3-93TGY-2PMBT
		uuid.UUID("8c762649-97d1-4953-ad27-b7e2c25b972e") : "PowerPoint 2013", #4NT99-8RJFH-Q2VDH-KYG2C-4RD4F
		uuid.UUID("00c79ff1-6850-443d-bf61-71cde0de305f") : "Publisher 2013", #PN2WF-29XG2-T9HJ7-JQPJR-FCXK4
		uuid.UUID("d9f5b1c6-5386-495a-88f9-9ad6b41ac9b3") : "Word 2013", #6Q7VD-NX8JD-WJ2VH-88V73-4GBJ7
		uuid.UUID("6f327760-8c5c-417c-9b61-836a98287e0c") : "Office 2010 Professional Plus", #VYBBJ-TRJPB-QFQRF-QFT4D-H3GVB
		uuid.UUID("9da2a678-fb6b-4e67-ab84-60dd6a9c819a") : "Office 2010 Standard", #V7QKV-4XVVR-XYV4D-F7DFM-8R6BM
		uuid.UUID("8ce7e872-188c-4b98-9d90-f8f90b7aad02") : "Access 2010", #V7Y44-9T38C-R2VJK-666HK-T7DDX
		uuid.UUID("cee5d470-6e3b-4fcc-8c2b-d17428568a9f") : "Excel 2010", #H62QG-HXVKF-PP4HP-66KMR-CW9BM
		uuid.UUID("8947d0b8-c33b-43e1-8c56-9b674c052832") : "SharePoint Workspace 2010 (Groove)", #QYYW6-QP4CB-MBV6G-HYMCJ-4T3J4
		uuid.UUID("ca6b6639-4ad6-40ae-a575-14dee07f6430") : "InfoPath 2010", #K96W8-67RPQ-62T9Y-J8FQJ-BT37T
		uuid.UUID("ab586f5c-5256-4632-962f-fefd8b49e6f4") : "OneNote 2010", #Q4Y4M-RHWJM-PY37F-MTKWH-D3XHX
		uuid.UUID("ecb7c192-73ab-4ded-acf4-2399b095d0cc") : "Outlook 2010", #7YDC2-CWM8M-RRTJC-8MDVC-X3DWQ
		uuid.UUID("45593b1d-dfb1-4e91-bbfb-2d5d0ce2227a") : "PowerPoint 2010", #RC8FX-88JRY-3PF7C-X8P67-P4VTT
		uuid.UUID("df133ff7-bf14-4f95-afe3-7b48e7e331ef") : "Project 2010 Professional", #YGX6F-PGV49-PGW3J-9BTGG-VHKC6
		uuid.UUID("5dc7bf61-5ec9-4996-9ccb-df806a2d0efe") : "Project 2010 Standard", #4HP3K-88W3F-W2K3D-6677X-F9PGB
		uuid.UUID("b50c4f75-599b-43e8-8dcd-1081a7967241") : "Publisher 2010", #BFK7F-9MYHM-V68C7-DRQ66-83YTP
		uuid.UUID("2d0882e7-a4e7-423b-8ccc-70d91e0158b1") : "Word 2010", #HVHB3-C6FV7-KQX9W-YQG79-CRY7T
		uuid.UUID("92236105-bb67-494f-94c7-7f7a607929bd") : "Visio 2010 Premium", #D9DWC-HPYVV-JGF4P-BTWQB-WX8BJ
		uuid.UUID("e558389c-83c3-4b29-adfe-5e4d7f46c358") : "Visio 2010 Professional", #7MCW8-VRQVK-G677T-PDJCM-Q8TCP
		uuid.UUID("9ed833ff-4f92-4f36-b370-8683a4f13275") : "Visio 2010 Standard", #767HD-QGMWX-8QTDB-9G3R2-KHFGJ
		uuid.UUID("ea509e87-07a1-4a45-9edc-eba5a39f36af") : "Office 2010 Home and Business", #D6QFG-VBYP2-XQHM7-J97RH-VVRCK
		uuid.UUID("09ed9640-f020-400a-acd8-d7d867dfd9c2") : "Office 2010 Mondo", #YBJTT-JG6MD-V9Q7P-DBKXJ-38W9R
		uuid.UUID("ef3d4e49-a53d-4d81-a2b1-2ca6c2556b2c") : "Office 2010 Mondo", #7TC2V-WXF6P-TD7RT-BQRXR-B8K32
		uuid.UUID("58e97c99-f377-4ef1-81d5-4ad5522b5fd8") : "Windows 10 Home", #TX9XD-98N7V-6WMQ6-BX7FG-H8Q99
		uuid.UUID("7b9e1751-a8da-4f75-9560-5fadfe3d8e38") : "Windows 10 Home N", #3KHY7-WNT83-DGQKR-F7HPR-844BM
		uuid.UUID("cd918a57-a41b-4c82-8dce-1a538e221a83") : "Windows 10 Home Single Language", #7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH
		uuid.UUID("a9107544-f4a0-4053-a96a-1479abdef912") : "Windows 10 Home Country Specific", #PVMJN-6DFY6-9CCP6-7BKTT-D3WVR
		uuid.UUID("2de67392-b7a7-462a-b1ca-108dd189f588") : "Windows 10 Professional", #W269N-WFGWX-YVC9B-4J6C9-T83GX
		uuid.UUID("a80b5abf-76ad-428b-b05d-a47d2dffeebf") : "Windows 10 Professional N", #MH37W-N47XK-V7XM9-C7227-GCQG9
		uuid.UUID("3f1afc82-f8ac-4f6c-8005-1d233e606eee") : "Windows 10 Professional Education", #6TP4R-GNPTD-KYYHQ-7B7DP-J447Y
		uuid.UUID("5300b18c-2e33-4dc2-8291-47ffcec746dd") : "Windows 10 Professional Education N", #YVWGF-BXNMC-HTQYQ-CPQ99-66QFC
		uuid.UUID("82bbc092-bc50-4e16-8e18-b74fc486aec3") : "Windows 10 Professional Workstation", #NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J
		uuid.UUID("4b1571d3-bafb-4b40-8087-a961be2caf65") : "Windows 10 Professional Workstation N", #9FNHH-K3HBT-3W4TD-6383H-6XYWF
		uuid.UUID("e0c42288-980c-4788-a014-c080d2e1926e") : "Windows 10 Education", #NW6C2-QMPVW-D7KKK-3GKT6-VCFB2
		uuid.UUID("3c102355-d027-42c6-ad23-2e7ef8a02585") : "Windows 10 Education N", #2WH4N-8QGBV-H22JP-CT43Q-MDWWJ
		uuid.UUID("73111121-5638-40f6-bc11-f1d7b0d64300") : "Windows 10 Enterprise", #NPPR9-FWDCX-D2C8J-H872K-2YT43
		uuid.UUID("e272e3e2-732f-4c65-a8f0-484747d0d947") : "Windows 10 Enterprise N", #DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4
		uuid.UUID("e0b2d383-d112-413f-8a80-97f373a5820c") : "Windows 10 Enterprise G", #YYVX9-NTFWV-6MDM3-9PT4T-4M68B
		uuid.UUID("e38454fb-41a4-4f59-a5dc-25080e354730") : "Windows 10 Enterprise G N", #44RPN-FTY23-9VTTB-MP9BX-T84FV
		uuid.UUID("7b51a46c-0c04-4e8f-9af4-8496cca90d5e") : "Windows 10 Enterprise 2015 LTSB", #WNMTR-4C88C-JK8YV-HQ7T2-76DF9
		uuid.UUID("87b838b7-41b6-4590-8318-5797951d8529") : "Windows 10 Enterprise 2015 LTSB N", #2F77B-TNFGY-69QQF-B8YKP-D69TJ
		uuid.UUID("2d5a5a60-3040-48bf-beb0-fcd770c20ce0") : "Windows 10 Enterprise 2016 LTSB", #DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ
		uuid.UUID("9f776d83-7156-45b2-8a5c-359b9c9f22a3") : "Windows 10 Enterprise 2016 LTSB N", #QFFDN-GRT3P-VKWWX-X7T3R-8B639
		uuid.UUID("32d2fab3-e4a8-42c2-923b-4bf4fd13e6ee") : "Windows 10 Enterprise LTSC 2018", #M7XTQ-FN8P6-TTKYV-9D4CC-J462D
		uuid.UUID("7103a333-b8c8-49cc-93ce-d37c09687f92") : "Windows 10 Enterprise LTSC 2018 N", #92NFX-8DJQP-P6BBQ-THF9C-7CG2H
		uuid.UUID("e4db50ea-bda1-4566-b047-0ca50abc6f07") : "Windows 10 Enterprise Remote Server", #7NBT4-WGBQX-MP4H7-QXFF8-YP3KX
		uuid.UUID("ec868e65-fadf-4759-b23e-93fe37f2cc29") : "Windows 10 Enterprise for Remote Sessions", #CPWHC-NT2C7-VYW78-DHDB2-PG3GK
		uuid.UUID("0df4f814-3f57-4b8b-9a9d-fddadcd69fac") : "Windows 10 Lean", #NBTWJ-3DR69-3C4V8-C26MC-GQ9M6
		uuid.UUID("034d3cbb-5d4b-4245-b3f8-f84571314078") : "Windows Server 2019 Essentials", #WVDHN-86M7X-466P6-VHXV7-YY726
		uuid.UUID("de32eafd-aaee-4662-9444-c1befb41bde2") : "Windows Server 2019 Standard", #N69G4-B89J2-4G8F4-WWYCC-J464C
		uuid.UUID("34e1ae55-27f8-4950-8877-7a03be5fb181") : "Windows Server 2019 Datacenter", #WMDGN-G9PQG-XVVXX-R3X43-63DFG
		uuid.UUID("73e3957c-fc0c-400d-9184-5f7b6f2eb409") : "Windows Server 2019 Standard ACor", #N2KJX-J94YW-TQVFB-DG9YT-724CC
		uuid.UUID("90c362e5-0da1-4bfd-b53b-b87d309ade43") : "Windows Server 2019 Datacenter ACor", #6NMRW-2C8FM-D24W7-TQWMY-CWH2D
		uuid.UUID("a99cc1f0-7719-4306-9645-294102fbff95") : "Windows Server 2019 Azure Core", #FDNH6-VW9RW-BXPJ7-4XTYG-239TB
		uuid.UUID("8de8eb62-bbe0-40ac-ac17-f75595071ea3") : "Windows Server 2019 ARM64", #GRFBW-QNDC4-6QBHG-CCK3B-2PR88
		uuid.UUID("2b5a1b0f-a5ab-4c54-ac2f-a6d94824a283") : "Windows Server 2016 Essentials", #JCKRF-N37P4-C2D82-9YXRT-4M63B
		uuid.UUID("8c1c5410-9f39-4805-8c9d-63a07706358f") : "Windows Server 2016 Standard", #WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY
		uuid.UUID("21c56779-b449-4d20-adfc-eece0e1ad74b") : "Windows Server 2016 Datacenter", #CB7KF-BWN84-R7R2Y-793K2-8XDDG
		uuid.UUID("61c5ef22-f14f-4553-a824-c4b31e84b100") : "Windows Server 2016 Standard ACor", #PTXN8-JFHJM-4WC78-MPCBR-9W4KR
		uuid.UUID("e49c08e7-da82-42f8-bde2-b570fbcae76c") : "Windows Server 2016 Datacenter ACor", #2HXDN-KRXHB-GPYC7-YCKFJ-7FVDG
		uuid.UUID("7b4433f4-b1e7-4788-895a-c45378d38253") : "Windows Server 2016 Cloud Storage", #QN4C6-GBJD2-FB422-GHWJK-GJG2R
		uuid.UUID("3dbf341b-5f6c-4fa7-b936-699dce9e263f") : "Windows Server 2016 Azure Core", #VP34G-4NPPG-79JTQ-864T4-R3MQX
		uuid.UUID("43d9af6e-5e86-4be8-a797-d072a046896c") : "Windows Server 2016 ARM64", #K9FYF-G6NCK-73M32-XMVPY-F9DRR
		uuid.UUID("c06b6981-d7fd-4a35-b7b4-054742b7af67") : "Windows 8.1 Professional", #GCRJD-8NW9H-F2CDX-CCM8D-9D6T9
		uuid.UUID("7476d79f-8e48-49b4-ab63-4d0b813a16e4") : "Windows 8.1 Professional N", #HMCNV-VVBFX-7HMBH-CTY9B-B4FXY
		uuid.UUID("81671aaf-79d1-4eb1-b004-8cbbe173afea") : "Windows 8.1 Enterprise", #MHF9N-XY6XB-WVXMC-BTDCT-MKKG7
		uuid.UUID("113e705c-fa49-48a4-beea-7dd879b46b14") : "Windows 8.1 Enterprise N", #TT4HM-HN7YT-62K67-RGRQJ-JFFXW
		uuid.UUID("096ce63d-4fac-48a9-82a9-61ae9e800e5f") : "Windows 8.1 Professional WMC", #789NJ-TQK6T-6XTH8-J39CJ-J8D3P
		uuid.UUID("fe1c3238-432a-43a1-8e25-97e7d1ef10f3") : "Windows 8.1 Core", #M9Q9P-WNJJT-6PXPY-DWX8H-6XWKK
		uuid.UUID("78558a64-dc19-43fe-a0d0-8075b2a370a3") : "Windows 8.1 Core N", #7B9N3-D94CG-YTVHR-QBPX3-RJP64
		uuid.UUID("ffee456a-cd87-4390-8e07-16146c672fd0") : "Windows 8.1 Core ARM", #XYTND-K6QKT-K2MRH-66RTM-43JKP
		uuid.UUID("c72c6a1d-f252-4e7e-bdd1-3fca342acb35") : "Windows 8.1 Core Single Language", #BB6NG-PQ82V-VRDPW-8XVD2-V8P66
		uuid.UUID("db78b74f-ef1c-4892-abfe-1e66b8231df6") : "Windows 8.1 Core Country Specific", #NCTT7-2RGK8-WMHRF-RY7YQ-JTXG3
		uuid.UUID("0ab82d54-47f4-4acb-818c-cc5bf0ecb649") : "Windows 8.1 Embedded Industry", #NMMPB-38DD4-R2823-62W8D-VXKJB
		uuid.UUID("cd4e2d9f-5059-4a50-a92d-05d5bb1267c7") : "Windows 8.1 Embedded Industry Enterprise", #FNFKF-PWTVT-9RC8H-32HB2-JB34X
		uuid.UUID("f7e88590-dfc7-4c78-bccb-6f3865b99d1a") : "Windows 8.1 Embedded Industry Automotive", #VHXM3-NR6FT-RY6RT-CK882-KW2CJ
		uuid.UUID("e9942b32-2e55-4197-b0bd-5ff58cba8860") : "Windows 8.1 Core Connected (with Bing)", #3PY8R-QHNP9-W7XQD-G6DPH-3J2C9
		uuid.UUID("c6ddecd6-2354-4c19-909b-306a3058484e") : "Windows 8.1 Core Connected N (with Bing)", #Q6HTR-N24GM-PMJFP-69CD8-2GXKR
		uuid.UUID("b8f5e3a3-ed33-4608-81e1-37d6c9dcfd9c") : "Windows 8.1 Core Connected Single Language (with Bing)", #KF37N-VDV38-GRRTV-XH8X6-6F3BB
		uuid.UUID("ba998212-460a-44db-bfb5-71bf09d1c68b") : "Windows 8.1 Core Connected Country Specific (with Bing)", #R962J-37N87-9VVK2-WJ74P-XTMHR
		uuid.UUID("e58d87b5-8126-4580-80fb-861b22f79296") : "Windows 8.1 Professional Student", #MX3RK-9HNGX-K3QKC-6PJ3F-W8D7B
		uuid.UUID("cab491c7-a918-4f60-b502-dab75e334f40") : "Windows 8.1 Professional Student N", #TNFGH-2R6PB-8XM3K-QYHX2-J4296
		uuid.UUID("b3ca044e-a358-4d68-9883-aaa2941aca99") : "Windows Server 2012 R2 Standard", #D2N9P-3P6X9-2R39C-7RTCD-MDVJX
		uuid.UUID("00091344-1ea4-4f37-b789-01750ba6988c") : "Windows Server 2012 R2 Datacenter", #W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9
		uuid.UUID("21db6ba4-9a7b-4a14-9e29-64a60c59301d") : "Windows Server 2012 R2 Essentials", #KNC87-3J2TX-XB4WP-VCPJV-M4FWM
		uuid.UUID("b743a2be-68d4-4dd3-af32-92425b7bb623") : "Windows Server 2012 R2 Cloud Storage", #3NPTF-33KPT-GGBPR-YX76B-39KDD
		uuid.UUID("a98bcd6d-5343-4603-8afe-5908e4611112") : "Windows 8 Professional", #NG4HW-VH26C-733KW-K6F98-J8CK4
		uuid.UUID("ebf245c1-29a8-4daf-9cb1-38dfc608a8c8") : "Windows 8 Professional N", #XCVCF-2NXM9-723PB-MHCB7-2RYQQ
		uuid.UUID("458e1bec-837a-45f6-b9d5-925ed5d299de") : "Windows 8 Enterprise", #32JNW-9KQ84-P47T8-D8GGY-CWCK7
		uuid.UUID("e14997e7-800a-4cf7-ad10-de4b45b578db") : "Windows 8 Enterprise N", #JMNMF-RHW7P-DMY6X-RF3DR-X2BQT
		uuid.UUID("a00018a3-f20f-4632-bf7c-8daa5351c914") : "Windows 8 Professional WMC", #GNBB8-YVD74-QJHX6-27H4K-8QHDG
		uuid.UUID("c04ed6bf-55c8-4b47-9f8e-5a1f31ceee60") : "Windows 8 Core", #BN3D2-R7TKB-3YPBD-8DRP2-27GG4
		uuid.UUID("197390a0-65f6-4a95-bdc4-55d58a3b0253") : "Windows 8 Core N", #8N2M2-HWPGY-7PGT9-HGDD8-GVGGY
		uuid.UUID("8860fcd4-a77b-4a20-9045-a150ff11d609") : "Windows 8 Core Single Language", #2WN2H-YGCQR-KFX6K-CD6TF-84YXQ
		uuid.UUID("9d5584a2-2d85-419a-982c-a00888bb9ddf") : "Windows 8 Core Country Specific", #4K36P-JN4VD-GDC6V-KDT89-DYFKP
		uuid.UUID("af35d7b7-5035-4b63-8972-f0b747b9f4dc") : "Windows 8 Core ARM", #DXHJF-N9KQX-MFPVR-GHGQK-Y7RKV
		uuid.UUID("10018baf-ce21-4060-80bd-47fe74ed4dab") : "Windows 8 Embedded Industry Professional", #RYXVT-BNQG7-VD29F-DBMRY-HT73M
		uuid.UUID("18db1848-12e0-4167-b9d7-da7fcda507db") : "Windows 8 Embedded Industry Enterprise", #NKB3R-R2F8T-3XCDP-7Q2KW-XWYQ2
		uuid.UUID("f0f5ec41-0d55-4732-af02-440a44a3cf0f") : "Windows Server 2012 Standard", #XC9B7-NBPP2-83J2H-RHMBY-92BT4
		uuid.UUID("d3643d60-0c42-412d-a7d6-52e6635327f6") : "Windows Server 2012 Datacenter", #48HP8-DN98B-MYWDG-T2DCC-8W83P
		uuid.UUID("7d5486c7-e120-4771-b7f1-7b56c6d3170c") : "Windows Server 2012 MultiPoint Standard", #HM7DN-YVMH3-46JC3-XYTG7-CYQJJ
		uuid.UUID("95fd1c83-7df5-494a-be8b-1300e1c9d1cd") : "Windows Server 2012 MultiPoint Premium", #XNH6W-2V9GX-RGJ4K-Y8X6F-QGJ2G
		uuid.UUID("b92e9980-b9d5-4821-9c94-140f632f6312") : "Windows 7 Professional", #FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4
		uuid.UUID("54a09a0d-d57b-4c10-8b69-a842d6590ad5") : "Windows 7 Professional N", #MRPKT-YTG23-K7D7T-X2JMM-QY7MG
		uuid.UUID("5a041529-fef8-4d07-b06f-b59b573b32d2") : "Windows 7 Professional E", #W82YF-2Q76Y-63HXB-FGJG9-GF7QX
		uuid.UUID("ae2ee509-1b34-41c0-acb7-6d4650168915") : "Windows 7 Enterprise", #33PXH-7Y6KF-2VJC9-XBBR8-HVTHH
		uuid.UUID("1cb6d605-11b3-4e14-bb30-da91c8e3983a") : "Windows 7 Enterprise N", #YDRBP-3D83W-TY26F-D46B2-XCKRJ
		uuid.UUID("46bbed08-9c7b-48fc-a614-95250573f4ea") : "Windows 7 Enterprise E", #C29WB-22CC8-VJ326-GHFJW-H9DH4
		uuid.UUID("db537896-376f-48ae-a492-53d0547773d0") : "Windows 7 Embedded POS Ready", #YBYF6-BHCR3-JPKRB-CDW7B-F9BK4
		uuid.UUID("aa6dd3aa-c2b4-40e2-a544-a6bbb3f5c395") : "Windows 7 Embedded ThinPC", #73KQT-CD9G6-K7TQG-66MRP-CQ22C
		uuid.UUID("e1a8296a-db37-44d1-8cce-7bc961d59c54") : "Windows 7 Embedded Standard", #XGY72-BRBBT-FF8MH-2GG8H-W7KCW
		uuid.UUID("a78b8bd9-8017-4df5-b86a-09f756affa7c") : "Windows Server 2008 R2 Web", #6TPJF-RBVHG-WBW2R-86QPH-6RTM4
		uuid.UUID("cda18cf3-c196-46ad-b289-60c072869994") : "Windows Server 2008 R2 HPC edition", #TT8MH-CG224-D3D7Q-498W2-9QCTX
		uuid.UUID("68531fb9-5511-4989-97be-d11a0f55633f") : "Windows Server 2008 R2 Standard", #YC6KT-GKW9T-YTKYR-T4X34-R7VHC
		uuid.UUID("620e2b3d-09e7-42fd-802a-17a13652fe7a") : "Windows Server 2008 R2 Enterprise", #489J6-VHDMP-X63PK-3K798-CPX3Y
		uuid.UUID("7482e61b-c589-4b7f-8ecc-46d455ac3b87") : "Windows Server 2008 R2 Datacenter", #74YFP-3QFB3-KQT8W-PMXWJ-7M648
		uuid.UUID("8a26851c-1c7e-48d3-a687-fbca9b9ac16b") : "Windows Server 2008 R2 for Itanium-based Systems", #GT63C-RJFQ3-4GMB6-BRFB9-CB83V
		uuid.UUID("f772515c-0e87-48d5-a676-e6962c3e1195") : "Windows MultiPoint Server 2010", #736RG-XDKJK-V34PF-BHK87-J6X3K
		uuid.UUID("4f3d1606-3fea-4c01-be3c-8d671c401e3b") : "Windows Vista Business", #YFKBB-PQJJV-G996G-VWGXY-2V3X8
		uuid.UUID("2c682dc2-8b68-4f63-a165-ae291d4cf138") : "Windows Vista Business N", #HMBQG-8H2RH-C77VX-27R82-VMQBT
		uuid.UUID("cfd8ff08-c0d7-452b-9f60-ef5c70c32094") : "Windows Vista Enterprise", #VKK3X-68KWM-X2YGT-QR4M6-4BWMV
		uuid.UUID("d4f54950-26f2-4fb4-ba21-ffab16afcade") : "Windows Vista Enterprise N", #VTC42-BM838-43QHV-84HX6-XJXKV
		uuid.UUID("ddfa9f7c-f09e-40b9-8c1a-be877a9a7f4b") : "Windows Server 2008 Web", #WYR28-R7TFJ-3X2YQ-YCY4H-M249D
		uuid.UUID("ad2542d4-9154-4c6d-8a44-30f11ee96989") : "Windows Server 2008 Standard", #TM24T-X9RMF-VWXK6-X8JC9-BFGM2
		uuid.UUID("2401e3d0-c50a-4b58-87b2-7e794b7d2607") : "Windows Server 2008 Standard without Hyper-V", #W7VD6-7JFBR-RX26B-YKQ3Y-6FFFJ
		uuid.UUID("c1af4d90-d1bc-44ca-85d4-003ba33db3b9") : "Windows Server 2008 Enterprise", #YQGMW-MPWTJ-34KDK-48M3W-X4Q6V
		uuid.UUID("8198490a-add0-47b2-b3ba-316b12d647b4") : "Windows Server 2008 Enterprise without Hyper-V", #39BXF-X8Q23-P2WWT-38T2F-G3FPG
		uuid.UUID("7afb1156-2c1d-40fc-b260-aab7442b62fe") : "Windows Server 2008 HPC (Compute Cluster)", #RCTX3-KWVHP-BR6TB-RB6DM-6X7HP
		uuid.UUID("68b6e220-cf09-466b-92d3-45cd964b9509") : "Windows Server 2008 Datacenter", #7M67G-PC374-GR742-YH8V4-TCBY3
		uuid.UUID("fd09ef77-5647-4eff-809c-af2b64659a45") : "Windows Server 2008 Datacenter without Hyper-V", #22XQ2-VRXRG-P8D42-K34TD-G3QQC
		uuid.UUID("01ef176b-3e0d-422a-b4f8-4ea880035e8f") : "Windows Server 2008 for Itanium-Based Systems", #4DWFP-JF3DJ-B7DTH-78FJB-PDRHK
	}

	licenseStates = {
		0 : "Unlicensed",
		1 : "Activated",
		2 : "Grace Period",
		3 : "Out-of-Tolerance Grace Period",
		4 : "Non-Genuine Grace Period",
		5 : "Notifications Mode",
		6 : "Extended Grace Period",
	}

	licenseStatesEnum = {
		'unlicensed' : 0,
		'licensed' : 1,
		'oobGrace' : 2,
		'ootGrace' : 3,
		'nonGenuineGrace' : 4,
		'notification' : 5,
		'extendedGrace' : 6
	}

	errorCodes = {
		'SL_E_VL_NOT_WINDOWS_SLP' : 0xC004F035,
		'SL_E_VL_NOT_ENOUGH_COUNT' : 0xC004F038,
		'SL_E_VL_BINDING_SERVICE_NOT_ENABLED' : 0xC004F039,
		'SL_E_VL_INFO_PRODUCT_USER_RIGHT' : 0x4004F040,
		'SL_I_VL_OOB_NO_BINDING_SERVER_REGISTRATION' : 0x4004F041,
		'SL_E_VL_KEY_MANAGEMENT_SERVICE_ID_MISMATCH' : 0xC004F042,
		'SL_E_VL_MACHINE_NOT_BOUND' : 0xC004F056
	}

	def __init__(self, data, config):
		self.data = data
		self.config = config

	def getConfig(self):
		return self.config

	def getOptions(self):
		return self.config

	def getData(self):
		return self.data

	def getResponse(self):
		return ''

	def getResponsePadding(self, bodyLength):
		if bodyLength % 8 == 0:
			paddingLength = 0
		else:
			paddingLength = 8 - bodyLength % 8
		padding = bytearray(paddingLength)
		return padding

	def serverLogic(self, kmsRequest):
		if self.config['debug']:
			print "KMS Request Bytes:", binascii.b2a_hex(str(kmsRequest))
			print "KMS Request:", kmsRequest.dump()

		if self.config['verbose']:
			clientMachineId = kmsRequest['clientMachineId'].get()
			applicationId = kmsRequest['applicationId'].get()
			skuId = kmsRequest['skuId'].get()
			requestDatetime = filetimes.filetime_to_dt(kmsRequest['requestTime'])

			# Try and localize the request time, if pytz is available
			try:
				import timezones
				from pytz import utc
				local_dt = utc.localize(requestDatetime).astimezone(timezones.localtz())
			except ImportError:
				local_dt = requestDatetime

			print "     Machine Name: %s" % kmsRequest.getMachineName()
			print "Client Machine ID: %s" % str(clientMachineId)
			print "   Application ID: %s" % self.appIds.get(applicationId, str(applicationId))
			print "           SKU ID: %s" % self.skuIds.get(skuId, str(skuId))
			print "   Licence Status: %s" % kmsRequest.getLicenseStatus()
			print "     Request Time: %s" % local_dt.strftime('%Y-%m-%d %H:%M:%S %Z (UTC%z)')

		return self.createKmsResponse(kmsRequest)

	def createKmsResponse(self, kmsRequest):
		response = self.kmsResponseStruct()
		response['versionMinor'] = kmsRequest['versionMinor']
		response['versionMajor'] = kmsRequest['versionMajor']

		if not self.config["epid"]:
			response["kmsEpid"] = kmsPidGenerator.epidGenerator(kmsRequest['applicationId'], kmsRequest['versionMajor'], self.config["lcid"]).encode('utf-16le')
		else:
			response["kmsEpid"] = self.config["epid"].encode('utf-16le')
		response['clientMachineId'] = kmsRequest['clientMachineId']
		response['responseTime'] = kmsRequest['requestTime']
		response['currentClientCount'] = self.config["CurrentClientCount"]
		response['vLActivationInterval'] = self.config["VLActivationInterval"]
		response['vLRenewalInterval'] = self.config["VLRenewalInterval"]
		if self.config['verbose']:
			print "      Server ePID: %s" % response["kmsEpid"].decode('utf-16le')
		return response

import kmsRequestV4, kmsRequestV5, kmsRequestV6, kmsRequestUnknown

def generateKmsResponseData(data, config):
	version = kmsBase.GenericRequestHeader(data)['versionMajor']
	currentDate = datetime.datetime.now().ctime()

	if version == 4:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV4.kmsRequestV4(data, config)
		messagehandler.executeRequestLogic()
	elif version == 5:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV5.kmsRequestV5(data, config)
		messagehandler.executeRequestLogic()
	elif version == 6:
		print "Received V%d request on %s." % (version, currentDate)
		messagehandler = kmsRequestV6.kmsRequestV6(data, config)
		messagehandler.executeRequestLogic()
	else:
		print "Unhandled KMS version.", version
		messagehandler = kmsRequestUnknown.kmsRequestUnknown(data, config)
	return messagehandler.getResponse()
