from dash import Dash, dcc, html
import plotly.express as px
import pandas as pd
import pandas as pd
import plotly.express as px
from utility import DataProcessorIPINFO
from dash import Dash, dcc, html, Input, Output
data_loader=DataProcessorIPINFO()
datainfo=data_loader.load_ipdata("ipinfodb.json")
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

key="pk.eyJ1IjoiYW1pdHR3IiwiYSI6ImNsY3o3Z2lnbDAwem8zd215YTQwa291cnMifQ.lxoWX6vYeDFRWf-zH1LD-w"
app = Dash(__name__, external_stylesheets=external_stylesheets)
histdata=pd.DataFrame(datainfo.Country.value_counts()).reset_index(drop=False)
k=sum(histdata.Country.values)
histdata.Country=(histdata.Country/sum(histdata.Country.values))*100
# see https://plotly.com/python/px-arguments/ for more options
## Plot at the start
hist = px.histogram(histdata, x="index",y="Country",title=" Country wise distribution of total " + str(k)+" Peers/Nodes/Neighbours" )
fig1 = px.scatter_mapbox(datainfo,
                    lat=datainfo.latitude,
                    lon=datainfo.longitude,
                    hover_name="IP",
                    color="Country",
                    hover_data=["org","domains"],
                    zoom=1,
                    size_max=20,
                    width=1500,                  
                    height=500)
fig1.update_layout(mapbox= dict(center=dict(lat=26,lon=80),
                           style="dark",accesstoken=key, 
                           zoom=1))
fig1.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
app.layout = html.Div(children=[
    html.H1(children='Blockchain Forensics'),
    html.Br(),
    html.H2(children='Peer Distribution Histogram',style={'margin-bottom': '0'}),
    dcc.Graph(id='histo', figure=hist),
    html.H2(children='Visualisation of Distribution on World map'),
    html.Div(children=''' Choose country to view peers from.'''),
    dcc.Dropdown(id="slct_country",
                 options=[{"label": "All Over World", "value": list(sorted(datainfo["Country"].unique()))}]+[{"label": x, "value": list([x])} for x in sorted(datainfo["Country"].unique())],
                 value="All Over World",
                 multi=False,
                 style={'width': "50%"},
                 clearable=False
                 ),
    html.Div(id='output_container', children=[]),
    dcc.Graph(id='my_map', figure=fig1),
    

], style={'margin-bottom': '50px'})

# Connect the Plotly graphs with Dash Components
@app.callback(
    [Output(component_id='output_container', component_property='children'),
     Output(component_id='my_map', component_property='figure')],
    [Input(component_id='slct_country', component_property='value')]
)
def update_graph(option_slctd):
    print(option_slctd)
    print(type(option_slctd))
    if len(option_slctd)>2:
        container = "Peers in: All over world"
    else:
        container = "Peers in: {}".format(option_slctd[0])
    dff = datainfo.copy()
    if len(option_slctd)<2:
       dff = dff[dff["Country"].isin(option_slctd)]
    else:
       return container, fig1
    
    # Plotly Express
    fig = px.scatter_mapbox(dff,
                        lat=dff.latitude,
                        lon=dff.longitude,
                        hover_name="IP",
                        color="IP",
                        zoom=1,
                        size_max=20,
                        width=1500,                  
                        height=500)
    fig.update_layout(mapbox= dict(center=dict(lat=dff.latitude.mean(),lon=dff.longitude.mean()),
                            style="dark",accesstoken=key, 
                            zoom=3))

    fig.update_layout(margin={"r":0,"t":0,"l":0,"b":0})
    return container, fig



if __name__ == '__main__':
    app.run_server(debug=False)