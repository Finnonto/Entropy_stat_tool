import statistic as dp
import csv



nf = ['orign','total',"distinct" ]
al = ['clifford','pingli']
pcap = ['CAIDA2007','MAWI2015']
plist = ['2007pcap.txt','2015pcap.txt']


title = ['type', 'srcIP', 'dstIP', 'sport', 'dport', 'proto', 'pktLen']
KLD_filename = 'All_KLD.csv'
Pearson_filename = 'All_Pearson.csv'
error_avg_filename = 'All_error_avg.csv'
error_std_filename = 'All_error_std.csv'
error_var_filename = 'All_error_var.csv'

All_KLD = []
All_Pearson = []
All_error_avg = []
All_error_std = []
All_error_var = []

for nf_ in nf :
    for p in pcap:
        for al_ in al :
            if p =='CAIDA2007':
                mydata = dp.data_process()
                mydata.main(
                        output_name="{1}2exact_{2}_{0}".format(nf_,al_,p),
                        base_filepath="{0}/exact_{1}_30/".format(p,nf_),
                        target_filepath="{2}/{1}_{0}_30/".format(nf_,al_,p),
                        pcap_namelist=plist[0]
                )
                
            else:
                mydata = dp.data_process()
                mydata.main(
                        output_name="{1}2exact_{2}_{0}".format(nf_,al_,p),
                        base_filepath="{0}/exact_{1}_30/".format(p,nf_),
                        target_filepath="{2}/{1}_{0}_30/".format(nf_,al_,p),
                        pcap_namelist=plist[1]
                )
                

                
           

            KLD_dict =  dict(
                    srcIP=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_srcIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_srcIP_value)) ),
                    dstIP=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_dstIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_dstIP_value)) ),
                    sport=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_sport_value), mydata.cnt_classify([0,]*len(mydata.deviation_sport_value)) ),
                    dport=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_dport_value), mydata.cnt_classify([0,]*len(mydata.deviation_dport_value)) ),
                    proto=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_proto_value), mydata.cnt_classify([0,]*len(mydata.deviation_proto_value)) ),
                    pktLen=mydata.cal_average_KL_scipy( mydata.cnt_classify(mydata.deviation_pktLen_value), mydata.cnt_classify([0,]*len(mydata.deviation_pktLen_value)) )
                        )

            Pearson_dict =  dict(
                    srcIP=mydata.Pearson( mydata.cnt_classify(mydata.deviation_srcIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_srcIP_value)) ),
                    dstIP=mydata.Pearson( mydata.cnt_classify(mydata.deviation_dstIP_value), mydata.cnt_classify([0,]*len(mydata.deviation_dstIP_value)) ),
                    sport=mydata.Pearson( mydata.cnt_classify(mydata.deviation_sport_value), mydata.cnt_classify([0,]*len(mydata.deviation_sport_value)) ),
                    dport=mydata.Pearson( mydata.cnt_classify(mydata.deviation_dport_value), mydata.cnt_classify([0,]*len(mydata.deviation_dport_value)) ),
                    proto=mydata.Pearson( mydata.cnt_classify(mydata.deviation_proto_value), mydata.cnt_classify([0,]*len(mydata.deviation_proto_value)) ),
                    pktLen=mydata.Pearson( mydata.cnt_classify(mydata.deviation_pktLen_value), mydata.cnt_classify([0,]*len(mydata.deviation_pktLen_value)) )
                        )

            error_stat =  dict(
                    srcIP=mydata.get_ave_sd(mydata.deviation_srcIP_value),
                    dstIP=mydata.get_ave_sd(mydata.deviation_dstIP_value),
                    sport=mydata.get_ave_sd(mydata.deviation_sport_value),
                    dport=mydata.get_ave_sd(mydata.deviation_dport_value),
                    proto=mydata.get_ave_sd(mydata.deviation_pktLen_value),
                    pktLen=mydata.get_ave_sd(mydata.deviation_proto_value),
                        )
            
                
            error_avg = [ 
                mydata.filename_format, error_stat['srcIP'][0], error_stat['dstIP'][0], error_stat['sport'][0], 
                                error_stat['dport'][0], error_stat['proto'][0], error_stat['pktLen'][0]    
            ]   


            error_std =  [ 
                mydata.filename_format, error_stat['srcIP'][1], error_stat['dstIP'][1], error_stat['sport'][1], 
                                error_stat['dport'][1], error_stat['proto'][1], error_stat['pktLen'][1]    
            ]   
            
            error_var =  [ 
                mydata.filename_format, error_stat['srcIP'][2], error_stat['dstIP'][2], error_stat['sport'][2], 
                                error_stat['dport'][2], error_stat['proto'][2], error_stat['pktLen'][2]    
            ]  

            All_error_avg.append(error_avg)
            All_error_std.append(error_std)
            All_error_var.append(error_var)
            KLD_data = [ 
                mydata.filename_format, KLD_dict['srcIP'], KLD_dict['dstIP'], KLD_dict['sport'], 
                                KLD_dict['dport'], KLD_dict['proto'], KLD_dict['pktLen'] 
            ]
            All_KLD.append(KLD_data)

            Pearson_data = [ 
                mydata.filename_format, Pearson_dict['srcIP'], Pearson_dict['dstIP'], Pearson_dict['sport'], 
                                Pearson_dict['dport'], Pearson_dict['proto'], Pearson_dict['pktLen'] 
            ]
            All_Pearson.append(Pearson_data)


with open(KLD_filename, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_KLD: writer.writerow(data)

with open(Pearson_filename, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_Pearson: writer.writerow(data)

with open(error_avg_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_error_avg: writer.writerow(data)

with open(error_std_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_error_std: writer.writerow(data)            

with open(error_var_filename , 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(title)
            
            for data in All_error_var: writer.writerow(data) 