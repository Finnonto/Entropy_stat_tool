import os 
import sys
import csv
import decimal as dec
import scipy.stats
import plotly
import plotly.figure_factory as ff
import math

class data_process():
    
    def __init__(self,normalization = 'orign'):
        
        #class parameter
        self.classifiation_reserved_digits = 2
        self.round_precision = 4
        self.nf = normalization #'total','distinct'
        #output parameter
        self.filename_format = ''
        self.output_dir = './' + self.filename_format + '/'
        self.plot_output_file_name = '{0}.html'.format(self.filename_format)
        self.csv_output_file_name = '{0}.csv'.format(self.filename_format)
        self.chart_title = '{0}'.format(self.filename_format)
        self.csv_title = ['type', 'srcIP', 'dstIP', 'sport', 'dport', 'proto', 'pktLen']
        # file parameter

        self.pcap = []

        #csv parameter
        self.mode = 'sec'
        self.time_interval = '30s'

        # plot parameter
        self.colors = ['rgba(0,0,255,1)', 'rgba(255,0,0,1)', 'rgba(34,177,76,1)', 
                    'rgba(153,51,255,1)', 'rgba(255,128,0,1)', 'rgba(204,204,0,1)']

        # calculation parameter
        self.exact_srcIP_entropy = []
        self.exact_dstIP_entropy = []
        self.exact_sport_entropy = []
        self.exact_dport_entropy = []
        self.exact_pktLen_entropy = []
        self.exact_proto_entropy = []

        self.est_srcIP_entropy = []
        self.est_dstIP_entropy = []
        self.est_sport_entropy = []
        self.est_dport_entropy = []
        self.est_pktLen_entropy = []
        self.est_proto_entropy = []

        self.deviation_srcIP_value = []
        self.deviation_dstIP_value = []
        self.deviation_sport_value = []
        self.deviation_dport_value = []
        self.deviation_pktLen_value = []
        self.deviation_proto_value = []

        self.deviation_percent_srcIP_value = []
        self.deviation_percent_dstIP_value = []
        self.deviation_percent_sport_value = []
        self.deviation_percent_dport_value = []
        self.deviation_percent_pktLen_value = []
        self.deviation_percent_proto_value = []

#################
#input functions#
#################
    def read_pcap(self,filename):
        f = open(filename,"r")
        self.pcap = f.read().splitlines()

    def read_csv(self,pcap,base_filepath,target_filepath):
        ## base
        
        for item in pcap:
            file_name = 'Analysis_'+ self.mode + '_' + self.time_interval + '_' + item
            print(base_filepath+file_name+'/'+file_name+'.csv')
            with open(base_filepath+file_name+'/'+file_name+'.csv', newline='') as fin:
                rows = csv.reader(fin)
                for row in rows:
                    
                    try:
                        if self.nf == 'orign' :self.exact_srcIP_entropy.append(float(row[1]))
                        elif self.nf == 'total':self.exact_srcIP_entropy.append(float(row[1])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.exact_srcIP_entropy.append(float(row[1])/math.log(float(row[2])))

                        if self.nf == 'orign' :self.exact_dstIP_entropy.append(float(row[3]))
                        elif self.nf == 'total':self.exact_dstIP_entropy.append(float(row[3])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.exact_dstIP_entropy.append(float(row[3])/math.log(float(row[4])))

                        if self.nf == 'orign' :self.exact_sport_entropy.append(float(row[5]))
                        elif self.nf == 'total':self.exact_sport_entropy.append(float(row[5])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.exact_sport_entropy.append(float(row[5])/math.log(float(row[6])))

                        if self.nf == 'orign' :self.exact_dport_entropy.append(float(row[7]))
                        elif self.nf == 'total':self.exact_dport_entropy.append(float(row[7])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.exact_dport_entropy.append(float(row[7])/math.log(float(row[8])))

                        if self.nf == 'orign' :self.exact_pktLen_entropy.append(float(row[11]))
                        elif self.nf == 'total':self.exact_pktLen_entropy.append(float(row[11])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.exact_pktLen_entropy.append(float(row[11])/math.log(float(row[12])))
                            
                        if self.nf == 'orign' :self.exact_proto_entropy.append(float(row[9]))
                        elif self.nf == 'total':self.exact_proto_entropy.append(float(row[9])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.exact_proto_entropy.append(float(row[9])/math.log(float(row[10])))
                        
                    except ValueError:
                        # text does not accept
                        pass
        ## target
        
        for item in pcap:
            file_name = 'Analysis_'+ self.mode + '_' + self.time_interval + '_' + item
            print(target_filepath+file_name+'/'+file_name+'.csv')
            with open(target_filepath+file_name+'/'+file_name+'.csv', newline='') as fin:
                rows = csv.reader(fin)
                for row in rows:
                    try:
                        if self.nf == 'orign' :self.est_srcIP_entropy.append(float(row[1]))
                        elif self.nf == 'total':self.est_srcIP_entropy.append(float(row[1])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.est_srcIP_entropy.append(float(row[1])/math.log(float(row[2])))

                        if self.nf == 'orign' :self.est_dstIP_entropy.append(float(row[3]))
                        elif self.nf == 'total':self.est_dstIP_entropy.append(float(row[3])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.est_dstIP_entropy.append(float(row[3])/math.log(float(row[4])))

                        if self.nf == 'orign' :self.est_sport_entropy.append(float(row[5]))
                        elif self.nf == 'total':self.est_sport_entropy.append(float(row[5])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.est_sport_entropy.append(float(row[5])/math.log(float(row[6])))

                        if self.nf == 'orign' :self.est_dport_entropy.append(float(row[7]))
                        elif self.nf == 'total':self.est_dport_entropy.append(float(row[7])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.est_dport_entropy.append(float(row[7])/math.log(float(row[8])))

                        if self.nf == 'orign' :self.est_pktLen_entropy.append(float(row[11]))
                        elif self.nf == 'total':self.est_pktLen_entropy.append(float(row[11])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.est_pktLen_entropy.append(float(row[11])/math.log(float(row[12])))
                            
                        if self.nf == 'orign' :self.est_proto_entropy.append(float(row[9]))
                        elif self.nf == 'total':self.est_proto_entropy.append(float(row[9])/math.log(float(row[15])))
                        elif self.nf == 'distinct':self.est_proto_entropy.append(float(row[9])/math.log(float(row[10])))
                    except ValueError:
                        # text does not accept
                        pass
    

##################
#data operations #
##################

    def _cal_deviation(self):
        ## entropy deviation
        for i in range(len(self.est_srcIP_entropy)):
            try: self.deviation_srcIP_value.append(self.est_srcIP_entropy[i]-self.exact_srcIP_entropy[i])
            except TypeError: self.deviation_srcIP_value.append(None)
            
            try: self.deviation_dstIP_value.append(self.est_dstIP_entropy[i]-self.exact_dstIP_entropy[i])
            except TypeError: self.deviation_dstIP_value.append(None)
            
            try: self.deviation_sport_value.append(self.est_sport_entropy[i]-self.exact_sport_entropy[i])
            except TypeError: self.deviation_sport_value.append(None)

            try: self.deviation_dport_value.append(self.est_dport_entropy[i]-self.exact_dport_entropy[i])
            except TypeError: self.deviation_dport_value.append(None)

            try: self.deviation_pktLen_value.append(self.est_pktLen_entropy[i]-self.exact_pktLen_entropy[i])
            except TypeError: self.deviation_pktLen_value.append(None)

            try: self.deviation_proto_value.append(self.est_proto_entropy[i]-self.exact_proto_entropy[i])
            except TypeError: self.deviation_proto_value.append(None)
        ## percent deviation
        for i in range(len(self.est_srcIP_entropy)):
            try: self.deviation_percent_srcIP_value.append(self.deviation_srcIP_value[i] / self.exact_srcIP_entropy[i])
            except TypeError: self.deviation_percent_srcIP_value.append(None)
            except ZeroDivisionError: self.deviation_percent_srcIP_value.append(self.deviation_srcIP_value[i] - self.exact_srcIP_entropy[i])
            
            try: self.deviation_percent_dstIP_value.append(self.deviation_dstIP_value[i] / self.exact_dstIP_entropy[i])
            except TypeError: self.deviation_percent_dstIP_value.append(None)
            except ZeroDivisionError: self.deviation_percent_dstIP_value.append(self.deviation_srcIP_value[i] - self.exact_srcIP_entropy[i])
            
            try: self.deviation_percent_sport_value.append(self.deviation_sport_value[i] / self.exact_sport_entropy[i])
            except TypeError: self.deviation_percent_sport_value.append(None)
            except ZeroDivisionError: self.deviation_percent_sport_value.append(self.deviation_srcIP_value[i] - self.exact_srcIP_entropy[i])

            try: self.deviation_percent_dport_value.append(self.deviation_dport_value[i] / self.exact_dport_entropy[i])
            except TypeError: self.deviation_percent_dport_value.append(None)
            except ZeroDivisionError: self.deviation_percent_dport_value.append(self.deviation_srcIP_value[i] - self.exact_srcIP_entropy[i])

            try: self.deviation_percent_pktLen_value.append(self.deviation_pktLen_value[i] / self.exact_pktLen_entropy[i])
            except TypeError: self.deviation_percent_pktLen_value.append(None)
            except ZeroDivisionError: self.deviation_percent_pktLen_value.append(self.deviation_srcIP_value[i] - self.exact_srcIP_entropy[i])

            try: self.deviation_percent_proto_value.append(self.deviation_proto_value[i] / self.exact_proto_entropy[i])
            except TypeError: self.deviation_percent_proto_value.append(None)
            except ZeroDivisionError: self.deviation_percent_proto_value.append(self.deviation_srcIP_value[i] - self.exact_srcIP_entropy[i])

    def cnt_classify(self,data):
        d_range = 3
        part = 10**self.classifiation_reserved_digits
        classification = [0.0001,]*part*2*d_range + [0.0001]
        
        for item in data:
            if item > d_range: item = dec.Decimal(d_range)
            if item < -d_range: item = dec.Decimal(-d_range)
            key = int(item*part) + d_range*part
            classification[key] += 1
            
        
        len_data = len(data)

        classification = [ item/len_data for item in classification ]
        
        return classification

    def cal_average_KL_scipy(self,a, b):
        distance_ab = scipy.stats.entropy(pk=a, qk=b, base=2)
        distance_ba = scipy.stats.entropy(pk=b, qk=a, base=2)
        return round(((distance_ab+distance_ba)/2),self.round_precision)

    def Pearson(self,a,b):
        return round(scipy.stats.pearsonr(a,b)[0],self.round_precision)

    def dis_percent(self,data):
        new_data = []
        for i in data:
            try: new_data.append( abs(i) )
            except TypeError: pass # ignore None
        new_data = sorted(new_data)

        # x axis, delete repeat items
        x_cdf_data = sorted( list( set(new_data) ) )
        
        # y axis
        y_cdf_data = []
        index = 0
        new_data_count = len(new_data)
        for i in x_cdf_data:
            appear_times = new_data.count(i)
            index += appear_times
            y_cdf_data.append( index/new_data_count*100 )
        
        return (x_cdf_data, y_cdf_data)

    def get_ave_sd(self,data):
        summ = 0
        sum_sqrt = 0
        cnt = 0
        for value in data:
            if value != None: 
                summ += value
                sum_sqrt += value**2
                cnt += 1
        average = summ / cnt
        var = (sum_sqrt/cnt) - (average**2)
        
        return (round(abs(average),self.round_precision), round(math.sqrt(var),self.round_precision) ,round(var,self.round_precision))

    def get_difference(self,data1,data2):
        diff = []
        for index in range(len(data1)):
            diff.append(round(abs(data1[index]-data2[index]),self.round_precision))

        return diff
##################
#output functions#
##################


    def plot_displot(self):

        hist_data = [
            self.deviation_srcIP_value, self.deviation_dstIP_value, self.deviation_sport_value, 
            self.deviation_dport_value, self.deviation_pktLen_value, self.deviation_proto_value
        ]
      
        group_labels = ['Source IP', 'Destination IP', 'Source Port', 'Destination Port', 'Packet Length', 'Protocol']

        ### remove  same items
        for data, label, color in zip(hist_data, group_labels, self.colors):
            if len( set(data) ) == 1:
                hist_data.remove(data)
                group_labels.remove(label)
                self.colors.remove(color)
        
        fig_distplot = ff.create_distplot(hist_data[::-1], group_labels[::-1], bin_size=0.001, colors=self.colors[::-1])
        fig_distplot.update_layout(
                                    title_text='Distplot_'+self.chart_title,
                                    xaxis=dict(title='deviation of Entropy'), 
                                    yaxis=dict(title='Permil (‰)'))
        
        plotly.offline.plot(
                            fig_distplot , 
                            filename= self.output_dir+ 'Distplot_'+self.plot_output_file_name, 
                            auto_open=False)

    def plot_cdf(self):
        cdf_dict = dict(
            srcIP=self.dis_percent(self.deviation_srcIP_value), 
            dstIP=self.dis_percent(self.deviation_dstIP_value),
            sport=self.dis_percent(self.deviation_sport_value),
            dport=self.dis_percent(self.deviation_dport_value),
            proto=self.dis_percent(self.deviation_proto_value),
            pktLen=self.dis_percent(self.deviation_pktLen_value)
        )

        cdf_data = [
            plotly.graph_objs.Scatter(x=cdf_dict['srcIP'][0], y=cdf_dict['srcIP'][1], 
                                        name='CDF of Source IP', marker={'color':self.colors[0]}, fill='tozeroy'),
            plotly.graph_objs.Scatter(x=cdf_dict['dstIP'][0], y=cdf_dict['dstIP'][1], 
                                        name='CDF of Destination IP', marker={'color':self.colors[1]}, fill='tozeroy'), 
            plotly.graph_objs.Scatter(x=cdf_dict['sport'][0], y=cdf_dict['sport'][1], 
                                        name='CDF of Source Port', marker={'color':self.colors[2]}, fill='tozeroy'), 
            plotly.graph_objs.Scatter(x=cdf_dict['dport'][0], y=cdf_dict['dport'][1], 
                                        name='CDF of Destination Port', marker={'color':self.colors[3]}, fill='tozeroy'), 
            plotly.graph_objs.Scatter(x=cdf_dict['pktLen'][0], y=cdf_dict['pktLen'][1], 
                                        name='CDF of Packet Length', marker={'color':self.colors[4]}, fill='tozeroy'), 
            plotly.graph_objs.Scatter(x=cdf_dict['proto'][0], y=cdf_dict['proto'][1], 
                                        name='CDF of Protocol', marker={'color':self.colors[5]}, fill='tozeroy')                             
        ]

        cdf_layout = plotly.graph_objs.Layout(
            title='CDF_'+self.chart_title,
            xaxis=dict(title='deviation', range=[0,3]), 
            yaxis=dict(title='Cumulative Percentage (%)'), 
            bargap=0
        )
        plotly.offline.plot(
            {'data': cdf_data, 'layout': cdf_layout}, 
            filename=self.output_dir+'CDF_'+self.plot_output_file_name, 
            auto_open=False
        )

    def write_KLD_csv(self):

        KLD_dict =  dict(
        srcIP=self.cal_average_KL_scipy( self.cnt_classify(self.deviation_srcIP_value), self.cnt_classify([0,]*len(self.deviation_srcIP_value)) ),
        dstIP=self.cal_average_KL_scipy( self.cnt_classify(self.deviation_dstIP_value), self.cnt_classify([0,]*len(self.deviation_dstIP_value)) ),
        sport=self.cal_average_KL_scipy( self.cnt_classify(self.deviation_sport_value), self.cnt_classify([0,]*len(self.deviation_sport_value)) ),
        dport=self.cal_average_KL_scipy( self.cnt_classify(self.deviation_dport_value), self.cnt_classify([0,]*len(self.deviation_dport_value)) ),
        proto=self.cal_average_KL_scipy( self.cnt_classify(self.deviation_proto_value), self.cnt_classify([0,]*len(self.deviation_proto_value)) ),
        pktLen=self.cal_average_KL_scipy( self.cnt_classify(self.deviation_pktLen_value), self.cnt_classify([0,]*len(self.deviation_pktLen_value)) )
             )

        with open(self.output_dir+self.csv_output_file_name, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(self.csv_title)
            
            
            csv_data = [ 
                self.filename_format, KLD_dict['srcIP'], KLD_dict['dstIP'], KLD_dict['sport'], 
                                KLD_dict['dport'], KLD_dict['proto'], KLD_dict['pktLen'] 
            ]
            writer.writerow(csv_data)

    def write_Pearson_csv(self):

        Pearson_dict =  dict(
        srcIP=self.Pearson( self.cnt_classify(self.deviation_srcIP_value), self.cnt_classify([0,]*len(self.deviation_srcIP_value)) ),
        dstIP=self.Pearson( self.cnt_classify(self.deviation_dstIP_value), self.cnt_classify([0,]*len(self.deviation_dstIP_value)) ),
        sport=self.Pearson( self.cnt_classify(self.deviation_sport_value), self.cnt_classify([0,]*len(self.deviation_sport_value)) ),
        dport=self.Pearson( self.cnt_classify(self.deviation_dport_value), self.cnt_classify([0,]*len(self.deviation_dport_value)) ),
        proto=self.Pearson( self.cnt_classify(self.deviation_proto_value), self.cnt_classify([0,]*len(self.deviation_proto_value)) ),
        pktLen=self.Pearson( self.cnt_classify(self.deviation_pktLen_value), self.cnt_classify([0,]*len(self.deviation_pktLen_value)) )
             )

        with open(self.output_dir+self.csv_output_file_name, 'w', encoding='utf-8') as fout:
            writer = csv.writer(fout, delimiter=',')
            writer.writerow(self.csv_title)
            
            
            csv_data = [ 
                self.filename_format, Pearson_dict['srcIP'], Pearson_dict['dstIP'], Pearson_dict['sport'], 
                                Pearson_dict['dport'], Pearson_dict['proto'], Pearson_dict['pktLen'] 
            ]
            writer.writerow(csv_data)

    def write_deviation_dis_info(self):
        with open(self.output_dir+ self.filename_format+'.txt', 'w') as fout:
            fout.write('Average / Standard Diviation\n\n')
            fout.write('Distplot_'+ self.filename_format+'\n')
            fout.write('Source IP:' + str(self.get_ave_sd(self.deviation_srcIP_value)) + '\n')
            fout.write('Destination IP:' + str(self.get_ave_sd(self.deviation_dstIP_value)) + '\n')
            fout.write('Source Port:' + str(self.get_ave_sd(self.deviation_sport_value)) + '\n')
            fout.write('Destination Port:' + str(self.get_ave_sd(self.deviation_dport_value)) + '\n')
            fout.write('Packet Length:' + str(self.get_ave_sd(self.deviation_pktLen_value)) + '\n')
            fout.write('Protocol:' + str(self.get_ave_sd(self.deviation_proto_value)) + '\n')

            fout.write('\n\n')

            fout.write('Distplot_percent_'+self.filename_format+'\n')
            fout.write('Source IP:' + str(self.get_ave_sd(self.deviation_percent_srcIP_value)) + '\n')
            fout.write('Destination IP:' + str(self.get_ave_sd(self.deviation_percent_dstIP_value)) + '\n')
            fout.write('Source Port:' + str(self.get_ave_sd(self.deviation_percent_sport_value)) + '\n')
            fout.write('Destination Port:' + str(self.get_ave_sd(self.deviation_percent_dport_value)) + '\n')
            fout.write('Packet Length:' + str(self.get_ave_sd(self.deviation_percent_pktLen_value)) + '\n')
            fout.write('Protocol:' + str(self.get_ave_sd(self.deviation_percent_proto_value)) + '\n')
    
    def __mkdir(self):
        os.system('mkdir {0}'.format(self.filename_format))        


################
#Main functions#
################
    def main(self,output_name,base_filepath,target_filepath,pcap_namelist):
        #init parameters
        dec.getcontext().prec = self.classifiation_reserved_digits
        self.filename_format = output_name
        self.output_dir = './' + self.filename_format + '/'
        self.plot_output_file_name = '{0}.html'.format(self.filename_format)
        self.csv_output_file_name = '{0}.csv'.format(self.filename_format)
        self.chart_title = '{0}'.format(self.filename_format)
     
        self.read_pcap(pcap_namelist)
        self.read_csv(self.pcap,base_filepath,target_filepath)
        # make new file
        #self.__mkdir()

        #data process
        self._cal_deviation()
'''
        self.write_Pearson_csv()
        self.write_KLD_csv()
        self.write_deviation_dis_info()
        self.plot_displot()
        self.plot_cdf()
'''       







if __name__ == '__main__':
    # read parameter
    # python3 statistic.py CAIDA2007/exact_orign_30/ CAIDA2007/pingli_orign_30/ 2007pcap.txt exact2pingli_2007_orign
    try:
        base_filepath = sys.argv[1]
        target_filepath = sys.argv[2]
        pcap_namelist = sys.argv[3]
        output_name = sys.argv[4]
    except IndexError:
        print('input error')
        exit(0)
    #preprocess
    my_data = data_process()
    my_data.main(output_name,base_filepath,target_filepath,pcap_namelist)